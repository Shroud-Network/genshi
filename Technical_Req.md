# shroud-honk: Technical Requirements & Development Context

> Derived from `README.md` (Technical Blueprint v0.1, March 2026).
> This file is the working reference for implementing the shroud-honk proving scheme.

---

## 1. Project Identity

| Field | Value |
|---|---|
| Name | `shroud-honk` |
| Type | Rust library crate (Cargo workspace) |
| Purpose | Rust-native UltraHonk proving scheme for Shroud Network privacy infrastructure |
| Target VMs | EVM (Ethereum, Avalanche, Monad, EVM L1s & L2s) + Solana |
| Primary runtime | Browser WASM (client-side proving) |
| Secondary runtime | Native binary (server-side proving) |
| Foundation | Arkworks ecosystem |

---

## 2. Problems Being Solved

1. **Proving speed** -- current Circom/Groth16/snarkjs stack takes minutes per transfer proof (WASM, no SIMD, wrong-field arithmetic).
2. **Wrong-field arithmetic** -- Baby Jubjub inside BN254 R1CS costs ~700 constraints per scalar mul.
3. **Per-circuit trusted setup** -- Groth16 requires a new ceremony for every circuit change.
4. **No lookup tables** -- R1CS cannot support plookup; range checks are expensive.
5. **Merkle tree depth** -- binary depth-20 tree = 20 Poseidon hashes per proof (~5,000 constraints).
6. **Sequential tree updates** -- single shared append-only tree serializes all operations.
7. **No server-side prover** -- browser-only proving with no fallback.
8. **Dual-VM requirement** -- one proving system must work on both EVM and Solana.

---

## 3. Architecture Decisions (Locked)

### 3.1 Proving System
- **UltraHonk** (PLONK-family with plookup lookup tables)
- Universal KZG setup (one Powers of Tau ceremony, never repeated)
- Custom gates beyond add/mul
- **No Noir** -- circuits written directly in Rust via constraint builder API

### 3.2 Commitment Curve
- **Grumpkin** replaces Baby Jubjub
- Grumpkin is BN254's cycle partner (scalar field = BN254 base field)
- Native arithmetic inside BN254 UltraHonk (~50 constraints per scalar mul vs ~700)
- Crate: `ark-grumpkin = "0.5"`

### 3.3 Hash Function
- **Poseidon2** replaces Poseidon
- Simpler round structure, faster natively and in-circuit
- Parameters defined once in `shroud-core/crypto/poseidon2.rs`, imported everywhere

### 3.4 Merkle Tree
- **4-ary Poseidon2 Merkle tree, depth 10**
- Same 1,048,576 leaf capacity as current binary depth-20
- ~1,500-2,000 constraints vs ~5,000 (50% depth reduction)

### 3.5 Transcript Hash
- **Keccak** for all verifiers (EVM and Solana)
- Ensures one proof format verifies on both VMs
- Keccak is native on EVM; slightly more expensive on Solana but acceptable for verification-only

### 3.6 SRS Source
- Aztec's Powers of Tau ceremony output (Barretenberg's existing ceremony)
- No custom ceremony
- Lazy SRS loading in WASM SDK; cache in IndexedDB after first download

---

## 4. Cryptographic Specifications

### 4.1 Note Structure

```
Note {
    amount: u64
    blinding: GrumpkinScalar             // random, Pedersen hiding factor
    secret: GrumpkinScalar               // random, owner-only knowledge
    nullifier_preimage: GrumpkinScalar   // random, never appears on-chain
    owner_public_key: GrumpkinPoint      // owner's public key on Grumpkin
    leaf_index: u64                      // position in Merkle tree
}
```

### 4.2 Note Commitment (Two-Layer)

```
Layer 1 -- Grumpkin Pedersen (native in BN254 UltraHonk):
    C = amount * G + blinding * H    (on Grumpkin curve)

Layer 2 -- Poseidon2 hash (goes into 4-ary Merkle tree):
    commitment = Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)
```

### 4.3 Nullifier Derivation

```
nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)
```

- Must be deterministic: same note always produces same nullifier
- Nullifier set is append-only and permanent

### 4.4 Pedersen Generators
- G and H on Grumpkin curve
- Derived via hash-to-curve from a nothing-up-my-sleeve seed
- Discrete log relationship between G and H must be unknown
- Derivation must be documented

---

## 5. Constraint Budget

| Group | Current (Circom/Groth16) | Target (Rust/UltraHonk) | Reduction |
|---|---|---|---|
| Ownership (scalar mul) | ~700 | ~50 (Grumpkin native) | 93% |
| Input Pedersen | ~1,400 | ~100 (Grumpkin native) | 93% |
| Note commitment | ~250 | ~150 (Poseidon2) | 40% |
| Merkle proof | ~5,000 | ~1,500 (4-ary depth 10) | 70% |
| Nullifier | ~250 | ~150 (Poseidon2) | 40% |
| Conservation checks | 2 | 2 | 0% |
| Range proofs | ~384 | ~50 (lookup table) | 87% |
| Output Pedersen x2 | ~2,800 | ~200 (Grumpkin native) | 93% |
| Output commitments x2 | ~500 | ~300 (Poseidon2) | 40% |
| **Total** | **~25,133** | **~2,500** | **~90%** |

**Performance target:** minutes -> under 5s client-side, under 2s server-side (50-100x speedup).

---

## 6. Crate Architecture

```
shroud-honk/                              -- Cargo workspace root
+-- crates/
|   +-- shroud-core/                      -- lib crate, no_std compatible
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
|   |   |   |   +-- verifier.rs            -- pure Rust verifier (Solana BPF target)
|   |   |   |   +-- kzg.rs
|   |   |   |   +-- srs.rs
|   |   |   +-- note.rs
|   |   +-- Cargo.toml
|   +-- shroud-wasm/                      -- cdylib crate, browser SDK
|   |   +-- src/lib.rs                    -- #[wasm_bindgen] exports
|   +-- shroud-evm/                       -- EVM verifier generation
|   |   +-- src/
|   |   |   +-- solidity_emitter.rs       -- generates Verifier.sol from vkey
|   |   |   +-- templates/                -- Solidity verifier template
|   |   +-- contracts/
|   |   |   +-- ShieldedPool.sol
|   |   +-- Cargo.toml
|   +-- shroud-solana/                    -- Anchor program
|   |   +-- src/crypto/mod.rs             -- re-exports shroud-core verifier
|   +-- shroud-cli/                       -- dev tooling only
|       +-- src/main.rs
+-- Cargo.toml
+-- benches/
    +-- transfer_proof.rs
```

### Critical Constraint
`shroud-core` **must be `no_std` compatible** -- this is what enables compilation to Solana BPF, browser WASM, and native targets from the same crate.

---

## 7. Dependencies

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

---

## 8. Dual-VM Deployment Matrix

| Component | EVM (Avalanche, Ethereum) | Solana |
|---|---|---|
| Proof generation | Browser WASM (`shroud-wasm`) | Browser WASM (`shroud-wasm`) |
| Proof format | UltraHonk, keccak transcript | UltraHonk, keccak transcript |
| On-chain verifier | Solidity (ecAdd/ecMul/ecPairing precompiles) | Rust BPF (`sol_alt_bn128_*` syscalls) |
| Verifier source | Generated by `shroud-evm` from vkey | Compiled from `shroud-core` verifier module |
| Merkle updates | Solidity (Poseidon2 in-contract) | Rust (`sol_poseidon` syscall or in-program) |
| Nullifier storage | `mapping(bytes32 => bool)` | PDA per nullifier (Light Protocol compressed) |
| Pool state | Solidity contract storage | PDA accounts |
| SDK | TypeScript, calls `shroud-wasm` | TypeScript, calls `shroud-wasm` |
| Verification cost | ~300-500K gas | ~800K-1.4M CU (estimated) |

**Proving side is 100% shared. SDK is 100% shared. Only on-chain contracts differ.**

---

## 9. Implementation Path

**Preferred: Path A -- Pure Rust implementation.**
- Build UltraHonk prover/verifier from scratch on Arkworks
- Reference: TaceoLabs co-snarks (Rust UltraHonk compatible with Barretenberg proof format)
- Full ownership, clean `no_std` and WASM compilation
- No C++ FFI dependency

**Fallback: Path B -- Barretenberg FFI hybrid.**
- Shroud circuits in pure Rust, UltraHonk proving via Barretenberg C++ FFI
- Faster to ship but complicates Solana BPF and browser WASM builds

---

## 10. Critical Guardrails (Security Invariants)

These are **non-negotiable**. Violation = protocol-level security failure.

| # | Invariant | Detail |
|---|---|---|
| G1 | Amount is never a public input in private transfer | Conservation proved inside the proof; amount is private witness only |
| G2 | Nullifier is deterministic and unique | `Poseidon2(nullifier_preimage, secret, leaf_index)` -- same note = same nullifier always |
| G3 | Commitment scheme is binding and hiding | Pedersen generators G, H must have unknown discrete log relationship |
| G4 | Merkle root validity | Circular buffer of recent valid roots (100); proof valid iff root in history |
| G5 | Poseidon2 parameters are canonical | One parameter set, imported everywhere, tested across all compilation targets |
| G6 | No cross-compilation parameter drift | `shroud-core` native/WASM/BPF must produce bit-identical outputs for identical inputs |
| G7 | One proof format, both VMs | Same proof bytes verify on EVM and Solana; keccak transcript on both chains |
| G8 | EVM precompile compatibility | Solidity verifier uses only ecAdd/ecMul/ecPairing/modexp -- no chain-specific opcodes |
| G9 | SRS integrity | Must come from verifiable ceremony (Aztec PoT); never generate custom SRS for production |
| G10 | Lookup table completeness | Every looked-up value must exist in table; no extra entries that enable range bypass |

---

## 11. Implementation Risks & Mitigations

### R1: UltraHonk Prover Correctness (HIGH)
- Permutation argument, plookup, KZG commits, Gemini, Shplonk -- subtle correctness requirements
- **Mitigation:** Cross-verify all proofs against Barretenberg/TaceoLabs reference; identical outputs required

### R2: Poseidon2 Parameter Mismatch (HIGHEST)
- Wrong parameters = silent failure (proofs verify against wrong Merkle roots)
- **Mitigation:** Single source of truth in `shroud-core/crypto/poseidon2.rs`; test hash outputs across native/WASM/BPF
- **Warning:** Solana `sol_poseidon` syscall implements Poseidon (not Poseidon2) -- parameter compatibility must be verified exhaustively

### R3: Grumpkin Migration Correctness
- Different field elements, curve points, group order, cofactor vs Baby Jubjub
- Pedersen generators must be deterministic hash-to-curve from NUMS seed
- **Mitigation:** Property-based tests for commitment opening, nullifier derivation, Merkle inclusion before building full circuit

### R4: WASM Performance
- SharedArrayBuffer required for parallel MSM; gated behind COOP/COEP headers
- Single-threaded WASM may only hit 10-20x speedup (not 50-100x)
- Browser WASM memory limit ~2-4GB
- **Mitigation:** Benchmark single-threaded WASM in Phase 4-5; fallback to server-side prover if threading unavailable

### R5: KZG SRS Distribution
- SRS must be downloaded to browser before proving
- Size scales with max circuit size (~few MB for 2,500 constraints)
- **Mitigation:** Lazy loading, IndexedDB caching, download only points needed for actual circuit size

### R6: Lookup Table Soundness
- Incorrect tables produce verifiable but unsound proofs
- **Mitigation:** Deterministic generation from circuit params; test that out-of-range values fail proof generation

### R7: Solana UltraHonk Verifier (HIGH)
- No production UltraHonk verifier exists for Solana yet
- CU budget unknown; Groth16 fits in 1.4M CU but UltraHonk may need more
- **Mitigation:** Implement in `shroud-core` as pure `no_std` Rust; benchmark CU on devnet early; consider split-verification or recursive wrapper if CU exceeds budget

### R8: EVM Verifier Migration
- Existing Avalanche Fuji deployment uses Groth16; must migrate to UltraHonk
- Existing testnet notes are NOT portable (curve and hash both changing)
- ~300-500K gas (1.5-2.5x Groth16); acceptable on Avalanche, watch for L1 Ethereum
- **Mitigation:** Use Barretenberg's Solidity verifier generation as reference; deploy on Fuji first

### R9: Dual-VM Proof Consistency
- Public input encoding differs: Solidity (big-endian, left-padded 32B) vs Solana Rust (little-endian field elements)
- **Mitigation:** Canonical public input serialization in `shroud-core`; per-chain encoding functions in respective crates

### R10: Witness Serialization & Privacy
- JS heap not securely erasable; browser extensions can inspect WASM memory
- **Mitigation:** Minimize witness lifetime in JS; host WASM from same origin; document limitations; recommend native CLI for high-security

### R11: Circuit Upgrade Path
- Circuit changes = new proving key, verification key, and on-chain verifier
- Note format and crypto derivations must be stable primitives independent of circuit
- **Mitigation:** Version vkeys; support multiple active vkeys on-chain during transitions

---

## 12. Build Sequence (Phased)

Each phase depends on correctness of the previous phase.

### Phase 1: Crypto Primitives (Week 1-2)
- [ ] Poseidon2 over BN254 scalar field with canonical parameters
- [ ] Grumpkin Pedersen commitment with documented generator derivation
- [ ] Test: hash outputs match Barretenberg reference vectors
- [ ] Test: commitment opens correctly; binding/hiding properties hold
- [ ] Test: all outputs identical across native, WASM, BPF targets

### Phase 2: Constraint System (Week 2-3)
- [ ] `UltraCircuitBuilder` (gate types, witness assignment, lookup table support)
- [ ] Plookup table construction for range proofs (64-bit)
- [ ] Test: manually constructed circuits produce valid witnesses
- [ ] Test: lookup table rejects out-of-range values

### Phase 3: Gadgets (Week 3-4)
- [ ] 4-ary Poseidon2 Merkle tree gadget
- [ ] Nullifier derivation gadget
- [ ] Note commitment gadget (Grumpkin Pedersen + Poseidon2)
- [ ] Range proof gadget via lookup table
- [ ] Test: each gadget in isolation with known inputs/outputs

### Phase 4: KZG & UltraHonk Prover/Verifier (Week 4-5)
- [ ] SRS loading from Aztec's Powers of Tau
- [ ] KZG polynomial commitment implementation
- [ ] UltraHonk proof generation and verification
- [ ] Test: prove/verify trivial circuit end-to-end
- [ ] Test: cross-verify proofs against Barretenberg/TaceoLabs

### Phase 5: Full Circuits (Week 5-7)
- [ ] Compose gadgets into Transfer and Withdraw circuits
- [ ] Test: full prove/verify cycle with real note data
- [ ] Benchmark: criterion benchmarks (native and WASM proving time)
- [ ] Memory profiling for WASM target

### Phase 6: Integration & Dual-VM Verification (Week 7-9)
- [ ] WASM build with `wasm-bindgen` exports for browser SDK
- [ ] Solana BPF build for on-chain verifier (`sol_alt_bn128_*` syscalls)
- [ ] Solidity verifier generation from vkey (adapt Barretenberg template)
- [ ] Deploy Solidity verifier on Avalanche Fuji; verify end-to-end
- [ ] Deploy Solana verifier on devnet; verify end-to-end
- [ ] Cross-VM proof test: one WASM proof, verify on both EVM and Solana
- [ ] Native server prover binary
- [ ] Full integration test: deposit -> transfer -> withdraw on both VMs

---

## 13. External References

| Resource | URL |
|---|---|
| Arkworks ecosystem | https://arkworks.rs |
| ark-grumpkin crate | https://crates.io/crates/ark-grumpkin |
| TaceoLabs co-snarks (Rust UltraHonk) | https://github.com/TaceoLabs/co-snarks |
| Barretenberg docs | https://barretenberg.aztec.network/docs |
| PLONK paper | https://eprint.iacr.org/2019/953 |
| Plookup paper | https://eprint.iacr.org/2020/315 |
| Grumpkin curve spec | https://hackmd.io/@aztec-network/ByzgNxBfd |

---

## 14. Out of Scope

- Cross-chain bridging between EVM and Solana
- Batch insertion / recursive proof aggregation (design-phase only)
- Relayer architecture (unchanged)
- SDK API surface (unchanged; only underlying prover changes)
- Token economics and protocol fees
- ShieldedPool migration on existing EVM testnet (new deployment, not upgrade)