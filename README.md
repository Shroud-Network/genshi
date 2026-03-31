# Shroud Network: Technical Blueprint

## shroud-honk -- A Rust-Native UltraHonk Proving Scheme for Privacy Infrastructure

Version 0.1 -- March 2026
Authors: Siddharth Manjul (CEO), Amit Sagar (CTO), Shroud Network

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

### 1.8 Proving System Must Work on Both EVM and Solana

Shroud is already deployed on EVM (Avalanche Fuji) with Groth16 verification. The Solana build is starting from scratch. The proving system selection must satisfy both VMs simultaneously.

On EVM, Groth16 verification uses BN254 precompiles (ecAdd, ecMul, ecPairing) at approximately 200K gas. UltraHonk verification uses the same precompiles at approximately 300-500K gas. Barretenberg already generates production Solidity verifiers for UltraHonk that are deployed in Aztec's own L1 verification pipeline.

On Solana, the `sol_alt_bn128_*` syscalls perform the same BN254 operations. Both Groth16 and UltraHonk verification use these syscalls, but the verifier logic differs. No production UltraHonk verifier for Solana exists yet, though TaceoLabs' co-snarks project provides a Rust-native UltraHonk prover compatible with Barretenberg that can be adapted.

The key constraint: the proving system must be chosen once and deployed on both chains. Running Groth16 on EVM and UltraHonk on Solana would mean different proof formats, different verification keys, and potentially different circuit structures, which fragments the SDK and doubles the maintenance burden.

### 1.9 EVM and Solana Cryptographic Consistency

Both VMs must use the same cryptographic stack: same commitment curve (Grumpkin), same hash function (Poseidon2), same note format, same nullifier derivation. If the EVM deployment uses different cryptographic primitives than Solana, the protocol fragments into two incompatible systems sharing a name but not interoperable at the note level. Every cryptographic decision made now applies to both chains simultaneously.

---

## Part 2: The Solution -- shroud-honk

### 2.1 Core Thesis

Instead of patching the current stack layer by layer, build one cohesive Rust-native proving implementation that targets all critical problems simultaneously. One codebase, one architecture, addressing proving speed, system architecture, wrong-field arithmetic, tree structure, and setup overhead in a single coordinated effort.

### 2.2 Architecture Overview

shroud-honk is a Rust library crate (not a binary) built on the Arkworks ecosystem, implementing UltraHonk arithmetization with Shroud-specific circuits. The scheme is VM-agnostic by design -- it produces proofs that can be verified on both EVM and Solana from a single proving stack.

It compiles to four targets from the same source: browser WASM for client-side proving (primary priority), a Solidity verifier contract for EVM chains (Avalanche, Ethereum, etc.), a Solana BPF program for on-chain verification via `sol_alt_bn128_*` syscalls, and a native binary for server-side proving.

The priority is client-side proving and verification. The entire design optimizes for browser WASM performance first, with server-side proving as a secondary target for fallback and batch operations.

### 2.2.1 Why Dual-VM Compatibility Is Architecturally Free

UltraHonk proofs are verified using BN254 elliptic curve pairings. Both the EVM and Solana have native support for exactly these operations:

On EVM, the precompiles ecAdd (0x06), ecMul (0x07), ecPairing (0x08), and modexp (0x05) are available on all major EVM chains including Avalanche, Ethereum, Arbitrum, Polygon, and Base. Barretenberg already generates production-ready Solidity verifier contracts that use these precompiles. UltraHonk verification on EVM costs approximately 300-500K gas, which is higher than Groth16's ~200K gas but entirely practical on Avalanche where gas is cheap.

On Solana, the `sol_alt_bn128_addition`, `sol_alt_bn128_multiplication`, and `sol_alt_bn128_pairing` syscalls (available since v1.16) perform the same BN254 operations at fixed compute unit costs. The verifier logic is written in Rust and compiled to BPF.

The proving side is identical for both chains. The same browser WASM prover generates the same proof bytes. The only difference is the verification contract: Solidity for EVM, Rust for Solana. The cryptographic scheme, note format, commitment structure, and nullifier derivation are completely chain-agnostic.

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

### 2.6 Dual-VM Deployment Map

| Component | EVM (Avalanche, Ethereum) | Solana |
|---|---|---|
| Proof generation | Browser WASM (shroud-wasm) | Browser WASM (shroud-wasm) |
| Proof format | UltraHonk, keccak transcript | UltraHonk, keccak transcript |
| On-chain verifier | Solidity contract using ecAdd/ecMul/ecPairing precompiles | Rust BPF program using sol_alt_bn128_* syscalls |
| Verifier source | Generated by shroud-evm from verification key | Compiled from shroud-core verifier module |
| Merkle tree updates | Solidity (Poseidon2 in-contract or precompile) | Rust (sol_poseidon syscall or in-program Poseidon2) |
| Nullifier storage | mapping(bytes32 => bool) in Solidity | PDA per nullifier (Light Protocol compressed) |
| Pool state | Solidity contract storage | PDA accounts |
| SDK | TypeScript, calls shroud-wasm | TypeScript, calls shroud-wasm |
| Gas/CU cost (verify) | ~300-500K gas | ~800K-1.4M CU (estimate, benchmark needed) |

The proving side is 100% shared. The SDK is 100% shared. Only the on-chain contracts differ, and they verify the same proof bytes against the same verification key encoded for their respective VM.

### 2.7 Crate Architecture

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
|   |   |   |   +-- verifier.rs          -- pure Rust verifier (Solana BPF target)
|   |   |   |   +-- kzg.rs
|   |   |   |   +-- srs.rs
|   |   |   +-- note.rs
|   |   +-- Cargo.toml
|   +-- shroud-wasm/                  -- cdylib crate, browser SDK
|   |   +-- src/lib.rs                -- #[wasm_bindgen] exports
|   +-- shroud-evm/                   -- EVM verifier generation
|   |   +-- src/
|   |   |   +-- solidity_emitter.rs   -- generates Verifier.sol from verification key
|   |   |   +-- templates/            -- Solidity verifier template with UltraHonk logic
|   |   +-- contracts/
|   |   |   +-- ShieldedPool.sol      -- pool contract importing generated verifier
|   |   +-- Cargo.toml
|   +-- shroud-solana/                -- Anchor program
|   |   +-- src/crypto/mod.rs         -- re-exports shroud-core verifier
|   +-- shroud-cli/                   -- dev tooling only, never deployed
|       +-- src/main.rs
+-- Cargo.toml
+-- benches/
    +-- transfer_proof.rs
```

The critical architectural constraint: `shroud-core` must be `no_std` compatible. This is what enables the same crate to compile for Solana's BPF target (no standard library), browser WASM, and native server binaries.

The EVM verifier (`shroud-evm`) is the exception to the pure-Rust rule. It outputs a Solidity contract that implements UltraHonk verification using EVM precompiles. This contract is generated from the verification key by a Rust build tool, not hand-written. The Solidity verifier is a static artifact -- it changes only when the circuit changes, not on every proof.

### 2.8 Dependencies

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

### 2.9 Implementation Path Options

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

### 3.7.1 EVM UltraHonk Verifier

The EVM verifier is a Solidity contract that implements UltraHonk verification using BN254 precompiles (ecAdd, ecMul, ecPairing, modexp). Barretenberg already generates production Solidity verifiers via `bb write_solidity_verifier`, and Aztec deploys UltraHonk verification to Ethereum L1 in production. The EVM path is more mature than the Solana path.

**Risks:**
- Gas cost for UltraHonk verification on EVM is approximately 300-500K gas, which is 1.5-2.5x more expensive than Groth16's ~200K gas. On Avalanche this is cheap (~$0.01-0.05), but on Ethereum mainnet it matters more. If Shroud targets L1 Ethereum in the future, gas optimization or a recursive UltraHonk-to-Groth16 wrapper may be needed.
- The generated Solidity verifier must use keccak as the transcript hash (not Poseidon2) because keccak is native to the EVM. The prover must use the `--oracle_hash keccak` flag when generating proofs intended for EVM verification. This means the proof bytes differ between EVM-targeted and Solana-targeted proofs if the Solana verifier uses Poseidon2 as the transcript hash.
- Shroud currently has a working EVM deployment on Avalanche Fuji with Groth16 verification. Migrating the on-chain verifier from Groth16 to UltraHonk requires a contract upgrade. Existing notes remain valid only if the note commitment scheme and nullifier derivation are unchanged at the cryptographic level -- the proof format changes but the underlying claims do not. However, since both the commitment curve (Baby Jubjub to Grumpkin) and the hash function (Poseidon to Poseidon2) are changing, existing EVM testnet notes will not be portable to the new scheme. This is acceptable on testnet but must be clearly communicated.

**Mitigation:** Use Barretenberg's Solidity verifier generation as a reference implementation, then adapt it to work with shroud-honk's proof format. The verification equation is public and well-documented. Test the Solidity verifier against the same test vectors used for the Rust verifier to ensure cross-VM proof compatibility. Deploy the Solidity verifier on Avalanche Fuji first and verify end-to-end before mainnet.

### 3.7.2 Dual-VM Proof Consistency

The same proof must verify correctly on both EVM and Solana. This requires careful attention to the transcript hash function used during proving.

**Risks:**
- If the EVM verifier uses keccak as the transcript hash and the Solana verifier uses Poseidon2, the same proof cannot verify on both chains. The prover would need to generate different proofs for different target chains, which breaks the "one proof, any chain" property.
- Public input encoding may differ between Solidity (big-endian, left-padded to 32 bytes) and Solana Rust (little-endian field elements). The SDK must serialize public inputs correctly for each chain.

**Mitigation:** Standardize on keccak as the transcript hash for all verifiers. Keccak is cheap on EVM (native opcode), and while it is more expensive than Poseidon2 in a Solana BPF program, it is only used during verification (not proving), and verification transcript hashing is a small fraction of the total verification compute. This ensures one proof format works on both VMs. Define a canonical public input serialization format in `shroud-core` and provide per-chain encoding functions in the respective crates.

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

## Part 4: Critical Guardrails

These are invariants that must never be violated. Breaking any of them is a protocol-level security failure.

### 4.1 Amount Must Never Be a Public Input in Private Transfer

The transfer circuit proves conservation of value (`amount_in == amount_out_1 + amount_out_2`) inside the proof. The amount is a private witness input, never exposed as a public input. If amount appears as a public input in the transfer instruction, privacy is broken at the protocol level. This applies to both EVM and Solana implementations.

### 4.2 Nullifier Must Be Deterministic and Unique

`Nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)`. This derivation must be deterministic -- the same note must always produce the same nullifier. If the nullifier derivation changes between circuit versions, spent notes could be re-spent. The nullifier set is append-only and permanent.

### 4.3 Commitment Scheme Must Be Binding and Hiding

The two-layer commitment (Pedersen on Grumpkin for homomorphism, Poseidon2 for Merkle leaf) must satisfy both computational binding (cannot open to two different values) and computational hiding (commitment reveals nothing about the committed value). Pedersen commitments require the discrete log relationship between generator points G and H to be unknown. Document the generator derivation (hash-to-curve from a nothing-up-my-sleeve seed) and never use generators with known discrete log relationships.

### 4.4 Merkle Root Validity

The on-chain root history must be a circular buffer of recently valid roots (currently 100). A proof is valid if and only if its claimed Merkle root exists in this history. If the buffer is too small, legitimate proofs generated against stale roots will fail. If the buffer is too large, it increases the window for certain timing attacks.

### 4.5 Poseidon2 Parameters Are Canonical

There is exactly one correct set of Poseidon2 parameters for Shroud. Every component that computes a Poseidon2 hash (circuit gadget, SDK client-side hasher, on-chain Merkle tree updater) must use identical parameters. Define them once, import everywhere, test across all compilation targets.

### 4.6 No Cross-Compilation Parameter Drift

`shroud-core` compiled to native, WASM, and BPF must produce identical outputs for identical inputs. Field arithmetic implementations can differ across targets (native may use assembly-optimized paths, WASM uses portable Rust), but the mathematical results must be bit-identical. The test suite must run on all three targets and compare outputs.

### 4.7 One Proof Format, Both VMs

A proof generated by the browser WASM prover must verify on both EVM (Solidity verifier) and Solana (Rust BPF verifier) without modification. This requires that the transcript hash, proof serialization format, and public input encoding are standardized across both verifiers. If the EVM and Solana verifiers ever diverge on what constitutes a valid proof, the scheme has failed its core dual-VM design goal. Use keccak as the transcript hash on both chains. Test every proof against both verifiers in CI.

### 4.8 EVM Precompile Compatibility

The Solidity verifier must only use BN254 precompiles available on all target EVM chains: ecAdd (0x06), ecMul (0x07), ecPairing (0x08), and modexp (0x05). Do not use chain-specific precompiles or opcodes that are not universally available. Verify the Solidity verifier deploys and verifies correctly on Avalanche C-Chain, Ethereum mainnet, and at least one L2 (Arbitrum or Base) before considering the EVM verifier complete.

### 4.9 SRS Integrity

The KZG Structured Reference String must come from a verifiable ceremony (Aztec's Powers of Tau or equivalent). If the SRS is compromised (the toxic waste is known), an attacker can forge arbitrary proofs. The SRS must be distributed with integrity verification (hash check against a known-good value). Never generate a custom SRS for production use.

### 4.10 Lookup Table Completeness

Every value that any circuit gate looks up must exist in the corresponding lookup table. A missing entry causes proof generation to fail (correct behavior). An extra entry that should not be in the table could enable range proof bypass (incorrect behavior). Lookup tables must be generated deterministically from the circuit parameters and verified against the proving key.

---

## Part 5: Build Sequence

This ordering matters. Each phase depends on the correctness of the previous one.

**Phase 1 (Week 1-2): Crypto Primitives**
- Poseidon2 over BN254 scalar field with canonical parameters
- Grumpkin Pedersen commitment with documented generator derivation
- Test: hash outputs match reference vectors from Barretenberg
- Test: commitment opens correctly, binding and hiding properties hold
- Test: all outputs identical across native, WASM, and BPF targets

**Phase 2 (Week 2-3): Constraint System**
- UltraCircuitBuilder (gate types, witness assignment, lookup table support)
- Plookup table construction for range proofs (64-bit)
- Test: manually constructed circuits produce valid witnesses
- Test: lookup table rejects out-of-range values

**Phase 3 (Week 3-4): Gadgets**
- 4-ary Poseidon2 Merkle tree gadget
- Nullifier derivation gadget
- Note commitment gadget (Grumpkin Pedersen + Poseidon2)
- Range proof gadget via lookup table
- Test: each gadget in isolation with known inputs and outputs

**Phase 4 (Week 4-5): KZG and UltraHonk Prover/Verifier**
- SRS loading from Aztec's Powers of Tau
- KZG polynomial commitment implementation
- UltraHonk proof generation and verification
- Test: prove and verify a trivial circuit end-to-end
- Test: cross-verify proofs against Barretenberg/TaceoLabs reference implementation

**Phase 5 (Week 5-7): Full Circuits**
- Compose gadgets into Transfer and Withdraw circuits
- Test: full prove/verify cycle with real note data
- Benchmark: criterion benchmarks for proving time (native and WASM)
- Memory profiling for WASM target

**Phase 6 (Week 7-9): Integration Targets and Dual-VM Verification**
- WASM build with wasm-bindgen exports for browser SDK
- Solana BPF build for on-chain verifier using `sol_alt_bn128_*` syscalls
- Solidity verifier generation from verification key (adapt Barretenberg's template)
- Deploy Solidity verifier on Avalanche Fuji, verify end-to-end
- Deploy Solana verifier on devnet, verify end-to-end
- Cross-VM proof test: generate one proof in browser WASM, verify on both EVM and Solana
- Native server prover binary
- Full integration test: deposit, transfer, withdraw cycle on both VMs

---

## Appendix A: What This Document Does Not Cover

- Cross-chain bridging between EVM and Solana deployments (the scheme produces proofs verifiable on both VMs independently, but cross-chain state synchronization is out of scope)
- Batch insertion and recursive proof aggregation (design-phase only, implement later)
- Relayer architecture (unchanged from current design, per-chain relayer instances)
- SDK API surface (unchanged, only the underlying prover changes)
- Token economics and protocol fees
- ShieldedPool contract migration from Groth16 to UltraHonk on existing EVM testnet (new deployment, not upgrade)

## Appendix B: Key External References

- Arkworks ecosystem: https://arkworks.rs
- ark-grumpkin crate: https://crates.io/crates/ark-grumpkin
- TaceoLabs co-snarks (Rust UltraHonk): https://github.com/TaceoLabs/co-snarks
- Barretenberg documentation: https://barretenberg.aztec.network/docs
- PLONK paper: https://eprint.iacr.org/2019/953
- Plookup paper: https://eprint.iacr.org/2020/315
- Grumpkin curve specification: https://hackmd.io/@aztec-network/ByzgNxBfd

## Appendix C: Constraint Notation

All constraint counts in this document are approximate and based on analysis of the current Circom circuits and published benchmarks for equivalent operations in UltraHonk. Actual constraint counts will be determined by the implementation and should be measured via criterion benchmarks in Phase 5.