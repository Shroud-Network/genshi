//! # genshi-math
//!
//! BN254 field, curve, and pairing abstraction used by the genshi verifier.
//!
//! The verifier is written exactly once against the types re-exported from this
//! crate (`Fr`, `G1Affine`, `G1Projective`, `G2Affine`, `pairing_check`).
//! Exactly one backend module is compiled in:
//!
//! - **`native`** (default) — zero-overhead wrappers over `ark_bn254`. Used
//!   for host-side proving/verifying and for WASM browser verification.
//! - **`bpf`** — hand-rolled Montgomery-form `Fr` plus thin wrappers over
//!   Solana's `sol_alt_bn128_*` syscalls for G1 / G2 / pairing. Used inside
//!   emitted Anchor programs to avoid pulling arkworks into BPF.
//!
//! The two backends are contractually byte-identical on inputs and outputs;
//! parity is enforced by cross-backend property tests in `tests/parity.rs`
//! (added in phase P2).
//!
//! ## Picking a backend
//!
//! ```toml
//! # host / wasm (default)
//! genshi-math = { version = "0.2" }
//!
//! # emitted Anchor program
//! genshi-math = { version = "0.2", default-features = false, features = ["bpf"] }
//! ```
//!
//! ## Backend contract (derived from the genshi verifier path)
//!
//! Both backends MUST expose the same names with the same observable behaviour.
//! The list below is the complete set of operations the verifier, transcript,
//! and on-chain SRS loader actually perform — any symbol not listed here does
//! not need a BPF implementation.
//!
//! ### `Fr` — scalar field of BN254
//!
//! Constructors:
//! - `Fr::zero()`, `Fr::one()`
//! - `Fr::from(u64)` — small-integer lift, used for `domain_size → Fr`.
//! - `Fr::from_be_bytes_mod_order(&[u8])` — 32-byte transcript challenge reduction.
//!
//! Arithmetic (binary ops return `Fr`; assign-ops mutate in place):
//! - `+`, `-`, `*`, `/`, unary `-`
//! - `+=`, `-=`, `*=`
//! - `pow(&[u64])` — used as `zeta.pow([n as u64])` (domain exponent).
//! - Implicit modular inverse via `/` (Fermat on BPF, `ark_ff::Field::inverse` on native).
//!
//! Predicates / comparison: `is_zero()`, `==`, `!=`.
//!
//! Serialization: 32-byte big-endian via `to_bytes_be()` (transcript absorb).
//!
//! ### `G1Affine` — elliptic curve over BN254 base field Fq
//!
//! Constructors: `G1Affine::generator()`, `G1Affine::zero()` (identity).
//!
//! Predicates: `is_zero()`, `==`.
//!
//! Conversions:
//! - `into_group()` → `G1Projective`
//! - Coordinate access: `x()`, `y()` returning `Option<Fq>`; only used by
//!   `transcript::absorb_point` to produce 64-byte `(x_be || y_be)` bytes.
//!   BPF backend can expose this as a single `to_uncompressed_bytes() -> [u8; 64]`
//!   helper rather than exposing Fq at all.
//!
//! Arithmetic: `*` (scalar mul by `Fr`) — used for `v·G₁` and `w·Fr`.
//!
//! Serialization (SRS load only, native-only path): uncompressed 64-byte form.
//!
//! ### `G1Projective`
//!
//! Constructors: `G1Projective::zero()`.
//!
//! Arithmetic: `+=` (projective), `-` (projective−projective), unary `-`,
//! `*` (by `Fr`).
//!
//! Conversion: `into_affine()` → `G1Affine`.
//!
//! ### `G2Affine`
//!
//! Constructors: `G2Affine::generator()` — only needed by the native SRS
//! generator; emitted Anchor programs hardcode `G2` and `G2_tau` as consts.
//!
//! Arithmetic: `*` (by `Fr`) → `G2Projective`.
//!
//! Conversion: `into_group()` → `G2Projective`.
//!
//! Serialization (native-only SRS load): uncompressed ~128-byte form.
//!
//! ### `G2Projective`
//!
//! Arithmetic: `-` (projective−projective) — used for `τ·G₂ − ζ·G₂`.
//!
//! Conversion: `into_affine()` → `G2Affine`.
//!
//! ### `pairing_check`
//!
//! Signature:
//! ```ignore
//! fn pairing_check(
//!     g1a: G1Affine, g2a: G2Affine,
//!     g1b: G1Affine, g2b: G2Affine,
//! ) -> bool;
//! ```
//! Returns `true` iff `e(g1a, g2a) · e(g1b, g2b) == 1` in GT. The verifier
//! always rewrites its two pairing equations into this one shape before
//! calling, so this is the entire pairing surface the BPF backend has to
//! cover via `sol_alt_bn128_pairing`.
//!
//! ### Not required on BPF
//!
//! - `G1Projective::msm` / `VariableBaseMSM` — only used by KZG `commit`,
//!   which is prover-side and feature-gated off for BPF.
//! - `CanonicalSerialize` / `CanonicalDeserialize` — SRS load happens on the
//!   host; emitted programs inline `G2` and `G2_tau` as big-endian byte consts.
//! - `Fq` direct access — the transcript only needs `G1Affine → [u8; 64]`,
//!   which BPF can implement without materialising an Fq type.

#![cfg_attr(not(feature = "native"), no_std)]

// Exactly one backend must be active. Enforce at compile time.
#[cfg(all(feature = "native", feature = "bpf"))]
compile_error!(
    "genshi-math: features `native` and `bpf` are mutually exclusive. \
     Disable default features and pick one."
);

#[cfg(not(any(feature = "native", feature = "bpf")))]
compile_error!(
    "genshi-math: one of the `native` or `bpf` features must be enabled."
);

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "bpf")]
pub mod bpf;

// ----------------------------------------------------------------------------
// Backend re-exports. Verifier code imports these names directly and never
// reaches into the backend modules — that's what keeps the verifier backend-
// agnostic and what lets the emitted Anchor program compile without arkworks.
// ----------------------------------------------------------------------------

#[cfg(feature = "native")]
pub use native::{Fr, G1Affine, G1Projective, G2Affine, G2Projective, keccak256, pairing_check};

#[cfg(feature = "bpf")]
pub use bpf::{Fr, G1Affine, G1Projective, G2Affine, G2Projective, keccak256, pairing_check};
