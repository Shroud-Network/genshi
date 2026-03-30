# Shroud Network ZK Scheme: Technical Blueprint
 
## shroud-honk -- A Rust-Native UltraHonk Proving Scheme for Privacy Infrastructure
 
Version 0.1 -- March 2026
Authors: Brooklyn (CTO), Shroud Network
 
---
 
## Part 1: The Problems We Are Solving
 
### 1.1 Proving Speed
 
Shroud's current transfer operation takes minutes to complete. The latency is entirely on the proving side, not the chain -- Avalanche Fuji confirms transactions in 2-3 seconds.
 
Three performance penalties compound on each other in the current stack. First, snarkjs executes Groth16 proof generation in WASM inside the browser with no SIMD vectorization, running 4-8x slower than native code. Second, Baby Jubjub arithmetic is wrong-field inside BN254 R1CS, meaning every scalar multiplication costs approximately 700 constraints instead of near-zero if the curve were native to the proof system. Third, the Merkle path verification at depth 20 costs approximately 5,000 constraints, making it the single largest constraint group.
 
The transfer circuit currently has approximately 25,133 total constraints, all paying the BN254 bignum arithmetic penalty. This is not a single bottleneck with a single fix. It is a systemic architecture problem where the proving system, the commitment curve, the hash function, and the tree structure are all suboptimal simultaneously.
 
### 1.2 Proving System Architecture
 
Groth16 combined with Circom is the wrong long-term stack for a privacy protocol under active development.
 
Circom requires manual constraint management where the developer thinks like a cryptographer rather than an engineer, making circuit development slow and auditing painful. Groth16 requires a per-circuit trusted setup ceremony, meaning every bug fix, optimization, or feature addition to either circuit requires coordinating a new ceremony. snarkjs is the only practical Groth16 prover in the browser, and it is slow by design. Most critically, Groth16's R1CS arithmetization has no support for lookup tables, which means wrong-field arithmetic can never be made cheap within this stack. This is a ceiling, not a fixable bug.
 
### 1.3 Baby Jubjub Wrong-Field Arithmetic
 
Baby Jubjub is a twisted Edwards curve defined over BN254's scalar field. Inside a BN254 R1CS circuit, all Baby Jubjub curve operations must be emulated as arithmetic constraints rather than executing natively. Every keypair derivation, every Pedersen commitment, and every ownership proof pays this penalty.
 
A single scalar multiplication on Baby Jubjub costs approximately 700 constraints. The same operation on a curve native to the proof system costs near-zero. Across the full transfer circuit, Baby Jubjub wrong-field operations account for roughly 5,600 constraints (ownership proof, input Pedersen, output Pedersens combined), which is over 22% of the total circuit cost spent purely on field incompatibility overhead.
 
### 1.4 Merkle Tree Depth and Structure
 
The current binary Merkle tree at depth 20 supports 1,048,576 commitments. On testnet, there are hundreds at most. Each Merkle proof requires 20 Poseidon hash verifications, costing approximately 5,000 constraints -- the single largest constraint group in the transfer circuit.
 
This capacity is unnecessary at the current stage and the tree structure is not optimized for constraint efficiency. A 4-ary tree at depth 10 covers the same 1M leaf capacity while halving the path length.
 
### 1.5 Sequential Merkle Tree Updates
 
The single shared append-only Merkle tree serializes all operations. Two users cannot transfer simultaneously because one must wait for the other's insertion to complete and the root to update before generating a valid proof against the current state.
 
The 100-root history buffer provides some tolerance for concurrent proof generation against slightly stale roots, but it does not solve high-throughput scenarios. There is no batching mechanism -- each transfer updates the tree once, paying full insertion cost per user.
 
### 1.6 No Server-Side Prover
 
All proving currently happens in the browser via snarkjs. There is no fallback for users on low-powered devices or when browser proving times out. A server-side prover introduces a privacy tradeoff because the server sees private witness inputs, which would require either a TEE (SGX enclave with remote attestation) or explicit user-facing disclosure.
 
### 1.7 Trusted Setup Operational Risk
 
Groth16 requires a new trusted setup ceremony every time either circuit changes. Any bug fix, optimization, or feature addition triggers a new ceremony requiring coordination, time, and community participation. Universal setup systems (UltraHonk with KZG, Halo2 with KZG) require one ceremony for all circuit sizes, eliminating this burden entirely.
 
### 1.8 Solana Proving System Selection
 
The Solana build is starting from scratch with an unresolved conflict: the initial design assumed Groth16 via `sol_alt_bn128_*` syscalls, but subsequent analysis identified UltraHonk as the correct long-term stack. UltraHonk verification on Solana still uses BN254 pairings (so the same syscalls apply), but the verifier logic is different from Groth16. No production UltraHonk verifier for Solana exists yet, though TaceoLabs' co-snarks project provides a Rust-native UltraHonk prover compatible with Barretenberg that can be adapted. This decision must be resolved before the Solana build progresses further, otherwise we build the wrong verifier.
 
### 1.9 EVM and Solana Cryptographic Divergence
 
If the EVM deployment migrates to Grumpkin for commitments (required for UltraHonk to eliminate wrong-field overhead) but the Solana deployment stays on Baby Jubjub for syscall compatibility, cross-chain note portability becomes impossible without a translation layer. Every cryptographic stack decision made now either opens or closes the door on future cross-chain interoperability.
 
---

## Part 2: The Solution -- shroud-honk
 
### 2.1 Core Thesis
 
Instead of patching the current stack layer by layer, build one cohesive Rust-native proving implementation that targets all critical problems simultaneously. One codebase, one architecture, addressing proving speed, system architecture, wrong-field arithmetic, tree structure, and setup overhead in a single coordinated effort.
 
### 2.2 Architecture Overview
 
shroud-honk is a Rust library crate (not a binary) built on the Arkworks ecosystem, implementing UltraHonk arithmetization with Shroud-specific circuits. It compiles to three targets from the same source: browser WASM for client-side proving, Solana BPF for on-chain verification, and native binary for server-side proving.
 
The priority is client-side proving and verification. The entire design optimizes for browser WASM performance first, with server-side proving as a secondary target for fallback and batch operations.
 
### 2.3 Technical Decisions
 
**Proving system: UltraHonk (PLONK-family with lookup tables)**
 
UltraHonk uses plookup-based lookup tables that make range checks and bit decompositions dramatically cheaper than R1CS. It uses a universal KZG setup (one Powers of Tau ceremony, never repeated). The arithmetization supports custom gates beyond simple addition and multiplication, enabling more efficient circuit designs for domain-specific operations like Poseidon hashing and Pedersen commitments.
 
**No Noir.** Noir is explicitly excluded due to language instability, frequent breaking changes, and painful circuit-level debugging. Circuits are written directly in Rust using a constraint builder API.
 
**Commitment curve: Grumpkin, replacing Baby Jubjub**
 
Grumpkin is BN254's cycle partner -- its scalar field equals BN254's base field and vice versa. Inside a BN254 UltraHonk proof, Grumpkin arithmetic is native rather than emulated. Scalar multiplications drop from approximately 700 constraints to approximately 50. Pedersen commitments drop from approximately 1,400 constraints to approximately 100.
 
The `ark-grumpkin` crate (v0.5.0) is published on crates.io with 250,000+ downloads, dual-licensed MIT/Apache, and maintained as part of the Arkworks algebra library.
 
**Hash function: Poseidon2**
 
Poseidon2 has a simpler round structure than Poseidon, making it both faster to compute natively and cheaper in constraints. Barretenberg already implements Poseidon2 as a native black box function. The migration from Poseidon to Poseidon2 changes hash outputs but not protocol semantics.
 
**Tree structure: 4-ary Poseidon2 Merkle tree, depth 10**
 
A 4-ary tree at depth 10 covers 1,048,576 leaves (identical capacity to the current binary tree at depth 20) while halving the number of hash operations per Merkle proof. Each node hashes 4 inputs instead of 2, which costs more per hash, but the 50% depth reduction more than compensates. Net constraint reduction for Merkle paths: approximately 5,000 to approximately 1,500-2,000.
 
### 2.4 Projected Constraint Reduction
 
| Constraint Group | Current (Circom/Groth16) | New (Rust/UltraHonk) | Reduction |
|---|---|---|---|
| Ownership (scalar mul) | ~700 | ~50 (Grumpkin native) | 93% |
| Input Pedersen | ~1,400 | ~100 (Grumpkin native) | 93% |
| Note commitment | ~250 | ~150 (Poseidon2) | 40% |
| Merkle proof | ~5,000 | ~1,500 (4-ary depth 10, Poseidon2) | 70% |
| Nullifier | ~250 | ~150 (Poseidon2) | 40% |
| Conservation checks | 2 | 2 | 0% |
| Range proofs | ~384 | ~50 (lookup table) | 87% |
| Output Pedersen x2 | ~2,800 | ~200 (Grumpkin native) | 93% |
| Output commitments x2 | ~500 | ~300 (Poseidon2) | 40% |
| **Total** | **~25,133** | **~2,500** | **~90%** |
 
Combined with UltraHonk's faster per-constraint prover performance and Rust-native WASM (Montgomery form arithmetic vs snarkjs bignum), the expected total speedup is 50-100x. Target: minutes to under 5 seconds client-side, under 2 seconds server-side.
 
### 2.5 Note Structure (New Format)
 
The protocol logic is identical to the current design. The only changes are the curve (Baby Jubjub to Grumpkin), the hash function (Poseidon to Poseidon2), and the tree arity (binary to 4-ary).
 
```
Note {
    amount: u64
    blinding: GrumpkinScalar           // random, Pedersen hiding factor
    secret: GrumpkinScalar             // random, owner-only knowledge
    nullifier_preimage: GrumpkinScalar // random, never appears on-chain
    owner_public_key: GrumpkinPoint    // owner's public key on Grumpkin
    leaf_index: u64                    // position in Merkle tree
}
 
NoteCommitment {
    // Layer 1: Grumpkin Pedersen (now native in BN254 UltraHonk)
    pedersen: GrumpkinPoint            // C = amount*G + blinding*H on Grumpkin
 
    // Layer 2: Poseidon2 hash (goes into 4-ary Merkle tree)
    commitment: BN254Scalar            // Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)
}
 
Nullifier {
    hash: BN254Scalar                  // Poseidon2(nullifier_preimage, secret, leaf_index)
}
```
 
### 2.6 Crate Architecture
 
```
shroud-honk/                          -- Cargo workspace root
+-- crates/
|   +-- shroud-core/                  -- lib crate, no_std compatible
|   |   +-- src/
|   |   |   +-- lib.rs
|   |   |   +-- arithmetization/
|   |   |   |   +-- ultra_circuit_builder.rs
|   |   |   |   +-- lookup_tables.rs
|   |   |   |   +-- witness.rs
|   |   |   +-- crypto/
|   |   |   |   +-- fields/
|   |   |   |   |   +-- bn254_scalar.rs
|   |   |   |   |   +-- bn254_base.rs
|   |   |   |   +-- curves/
|   |   |   |   |   +-- bn254.rs
|   |   |   |   |   +-- grumpkin.rs
|   |   |   |   +-- poseidon2.rs
|   |   |   |   +-- pedersen.rs
|   |   |   +-- circuits/
|   |   |   |   +-- gadgets/
|   |   |   |   |   +-- merkle.rs
|   |   |   |   |   +-- nullifier.rs
|   |   |   |   |   +-- note_commitment.rs
|   |   |   |   |   +-- range_proof.rs
|   |   |   |   +-- transfer.rs
|   |   |   |   +-- withdraw.rs
|   |   |   +-- proving/
|   |   |   |   +-- prover.rs
|   |   |   |   +-- verifier.rs
|   |   |   |   +-- kzg.rs
|   |   |   |   +-- srs.rs
|   |   |   +-- note.rs
|   |   +-- Cargo.toml
|   +-- shroud-wasm/                  -- cdylib crate, browser SDK
|   |   +-- src/lib.rs                -- #[wasm_bindgen] exports
|   +-- shroud-solana/                -- Anchor program
|   |   +-- src/crypto/mod.rs         -- re-exports shroud-core verifier
|   +-- shroud-cli/                   -- dev tooling only, never deployed
|       +-- src/main.rs
+-- Cargo.toml
+-- benches/
    +-- transfer_proof.rs
```
 
The critical architectural constraint: `shroud-core` must be `no_std` compatible. This is what enables the same crate to compile for Solana's BPF target (no standard library), browser WASM, and native server binaries.
 
### 2.7 Dependencies
 
```toml
[dependencies]
ark-bn254 = "0.5"
ark-grumpkin = "0.5"
ark-ff = "0.5"
ark-ec = "0.5"
ark-poly = "0.5"
ark-std = { version = "0.5", default-features = false }
ark-poly-commit = "0.5"
ark-serialize = "0.5"
 
[features]
default = ["std"]
std = ["ark-std/std", "ark-ff/std", "ark-ec/std"]
```
 
### 2.8 Implementation Path Options
 
There are two viable paths for the UltraHonk proving machinery itself:
 
**Path A: Pure Rust implementation.** Build the UltraHonk prover and verifier from scratch using Arkworks primitives. This gives full ownership and `no_std` compatibility across all targets. The TaceoLabs co-snarks project already contains a Rust rewrite of UltraHonk compatible with Barretenberg proof formats, which can serve as a reference or be forked and stripped of its MPC components. This is the preferred path for long-term independence.
 
**Path B: Barretenberg FFI hybrid.** Shroud's circuits and cryptographic primitives in pure Rust, UltraHonk proving machinery from Barretenberg's C++ library via FFI bindings (`barretenberg-rs` crate). Faster to ship, gets correctness from a battle-tested prover. Tradeoff: C++ dependency complicates Solana BPF compilation and introduces build complexity.
 
For client-side priority, Path A is strongly preferred because WASM compilation from pure Rust is clean and well-supported, while C++ FFI adds significant complexity to the browser build pipeline.
 
---