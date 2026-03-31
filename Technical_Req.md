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