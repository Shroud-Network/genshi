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