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
 
## Part 3: Implementation Risks and Pitfalls
 
### 3.1 UltraHonk Prover Correctness
 
Implementing UltraHonk's prover from scratch is the single hardest engineering task in this project. The protocol involves a permutation argument (copy constraints), plookup argument (lookup tables), KZG polynomial commitments, Gemini protocol (multilinear reduction), and Shplonk (batch opening). Each component has subtle correctness requirements where a single bug produces proofs that verify but are unsound, meaning an attacker could forge proofs.
 
**Mitigation:** Use TaceoLabs' co-snarks UltraHonk Rust implementation as a reference. Generate test vectors with Barretenberg's C++ implementation and verify shroud-honk produces identical proofs and verification results for the same inputs. Cross-verification against a known-correct implementation is non-negotiable before any deployment.
 
### 3.2 Poseidon2 Parameter Mismatch
 
This is the highest-risk correctness bug in the entire project. Poseidon2 hash outputs are determined by the exact parameters: number of full rounds, number of partial rounds, S-box exponent, MDS matrix, and round constants. If the circuit implementation uses different parameters than the on-chain implementation, all proofs fail silently -- they verify on-chain but against wrong Merkle roots, making legitimate notes unspendable while potentially making forged commitments appear valid.
 
**Mitigation:** Define canonical Poseidon2 parameters once in `shroud-core/crypto/poseidon2.rs`. The circuit gadget, the WASM SDK, and the on-chain contract all import from this single source. Build a dedicated test suite that hashes known inputs and compares outputs across all three compilation targets (native, WASM, BPF) before any other work proceeds. If using Solana's `sol_poseidon` syscall, verify parameter compatibility exhaustively because that syscall implements Poseidon (not Poseidon2), and parameter differences would be catastrophic.
 
### 3.3 Grumpkin Curve Migration Correctness
 
Replacing Baby Jubjub with Grumpkin changes the note format, keypair structure, and commitment scheme. While the protocol logic (deposit, transfer, withdraw, nullifier check, Merkle inclusion) is semantically identical, every cryptographic operation touches different field elements and curve points.
 
**Risks:**
- Pedersen generator points for Grumpkin must be generated deterministically and documented. Using incorrect or non-standard generators breaks binding or hiding properties.
- The two-layer commitment design (Pedersen on Grumpkin for homomorphism, Poseidon2 hash for Merkle leaf) must preserve the same security properties as the current Baby Jubjub + Poseidon design.
- Key derivation changes because Grumpkin has different group order and cofactor properties than Baby Jubjub.
 
**Mitigation:** Write property-based tests verifying that commitment opening, nullifier derivation, and Merkle inclusion proofs behave correctly end-to-end with the new curve before building the full circuit.
 
### 3.4 WASM Performance (Client-Side Priority)
 
The projected 50-100x speedup assumes Rust-native arithmetic compiled to WASM. However, WASM execution in browsers has its own constraints. WASM threads (SharedArrayBuffer) are required for parallel MSM computation but are gated behind Cross-Origin Isolation headers (COOP/COEP), which not all hosting environments support. Without threading, prover performance degrades significantly.
 
**Risks:**
- Single-threaded WASM may only achieve 10-20x speedup instead of 50-100x.
- Memory pressure in browser WASM (typically limited to 2-4GB) could cause proving to fail for larger circuits or batch operations.
- Arkworks' Montgomery form arithmetic is optimized for 64-bit native but may not vectorize efficiently in WASM's 32-bit linear memory model on older browsers.
 
**Mitigation:** Benchmark single-threaded WASM proving early (week 4-5 of the build) with realistic circuit sizes. If single-threaded performance is insufficient, design the SDK to detect SharedArrayBuffer availability and fall back to a server-side prover when threading is unavailable. Profile memory allocation during proving and optimize or stream intermediate polynomial evaluations if heap pressure is excessive.
 
### 3.5 KZG Structured Reference String (SRS) Distribution
 
UltraHonk with KZG requires a Structured Reference String (Powers of Tau) that must be available to every prover. For client-side proving, this SRS must be downloaded to the browser before proof generation can begin.
 
**Risks:**
- SRS size scales with the maximum supported circuit size. For a 2,500-constraint circuit the SRS is modest (a few MB), but if batch proving or future circuit growth pushes constraints higher, the SRS download becomes a UX bottleneck.
- The SRS must be loaded into WASM memory, competing with circuit witness and polynomial evaluation memory.
 
**Mitigation:** Use Barretenberg's existing Powers of Tau ceremony output (Aztec's universal setup) rather than running a custom ceremony. Implement lazy SRS loading in the WASM SDK -- download only the SRS points needed for the actual circuit size, not the full ceremony output. Cache the SRS in browser storage (IndexedDB) after first download.
 
### 3.6 Lookup Table Soundness
 
UltraHonk's plookup argument is what makes range proofs and bit decompositions cheap. However, lookup tables must be constructed correctly: every value the circuit looks up must exist in the table, and the table itself must be committed to as part of the proving key. An incorrectly constructed lookup table produces proofs that verify but are unsound.
 
**Risks:**
- Range proof lookup tables must cover exactly the required bit range (64-bit for amounts). A table that is too small allows values outside the expected range; a table that is too large wastes prover memory.
- Custom lookup tables for Poseidon2 S-box operations must match the exact S-box polynomial.
 
**Mitigation:** Generate lookup tables deterministically from parameters defined in `shroud-core`. Test that out-of-range values cause proof generation to fail (not succeed silently). Include lookup table verification in the cross-implementation test suite against Barretenberg.
 
### 3.7 Solana UltraHonk Verifier
 
No production UltraHonk verifier exists for Solana. While UltraHonk still uses BN254 pairings (meaning `sol_alt_bn128_*` syscalls apply), the verification equation is different from Groth16's `e(A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1`.
 
**Risks:**
- UltraHonk verification involves evaluating committed polynomials at a challenge point and checking a pairing equation that depends on the specific UltraHonk variant (sumcheck-based vs. original). The exact verification equation must match the prover's protocol version.
- Compute unit budget on Solana for UltraHonk verification is unknown. Groth16 verification via syscalls fits within 1.4M CU. UltraHonk verification may require more pairing operations depending on the protocol variant.
- The verifier must be compiled to Solana BPF, which has a restricted instruction set and no floating point.
 
**Mitigation:** Implement the verifier in `shroud-core` as pure Rust with `no_std` support. Benchmark compute unit consumption on Solana devnet early. If CU budget is insufficient, evaluate split-verification across multiple transactions or investigate whether a recursive UltraHonk-to-Groth16 wrapper is necessary for on-chain verification.
 
### 3.8 Witness Serialization and Privacy
 
For client-side proving, the witness (containing private keys, amounts, blinding factors, Merkle paths) must be constructed in JavaScript/TypeScript and passed to the WASM prover. The serialization boundary between JS and WASM is a potential information leak surface.
 
**Risks:**
- Witness data in JavaScript heap is not securely erasable. The JS garbage collector does not guarantee zeroing of deallocated memory.
- If the WASM module is loaded from a CDN or third-party source, a supply chain attack could exfiltrate witness data.
- Browser extensions can inspect WASM memory.
 
**Mitigation:** Minimize the time witness data exists in JavaScript memory -- construct and pass to WASM immediately, then overwrite the JS-side buffer. Host the WASM module from the same origin as the application. Document the browser-side privacy limitations clearly to users. For high-security use cases, recommend the native CLI prover.
 
### 3.9 Circuit Upgrade Path
 
Once deployed, any change to the circuit (bug fix, optimization, new feature) changes the proving key, verification key, and the on-chain verifier. Unlike Groth16, UltraHonk's universal setup means no new ceremony is needed, but the verifier contract still needs to be redeployed.
 
**Risks:**
- Notes created with the old circuit version use the old commitment and nullifier derivation. If the circuit changes alter how commitments or nullifiers are computed, existing notes become unspendable.
- On-chain verifier upgrade requires a governance or admin mechanism that could be a centralization vector.
 
**Mitigation:** Design the note format and cryptographic derivations (commitment, nullifier, Merkle leaf) as stable primitives that are independent of the circuit implementation. Circuit changes should only affect how the proof is generated and verified, not what is being proved. Version the proving key and verification key, and support multiple active verification keys on-chain during transition periods.
 
---