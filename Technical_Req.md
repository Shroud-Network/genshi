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