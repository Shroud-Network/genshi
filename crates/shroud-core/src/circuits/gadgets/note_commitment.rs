//! Note commitment gadget (Grumpkin Pedersen + Poseidon2).
//!
//! TODO: Phase 3 — Constrain the two-layer commitment:
//! Layer 1: C = amount * G + blinding * H (Grumpkin Pedersen, native ~100 constraints)
//! Layer 2: commitment = Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x) (~150 constraints)
