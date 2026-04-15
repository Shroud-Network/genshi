# Genshi — Framework Documentation

> **Consolidated reference.** This doc synthesizes `README.md`, `Technical_Req.md`,
> `implementation_plan.md`, and `GUIDE.md` into one place. For the full authoring
> walkthrough with code samples, see [`GUIDE.md`](GUIDE.md).

---

## 1. What genshi is

**genshi** (原始, jp. *origin; primordial; elemental*) is a Rust-native
zero-knowledge proving framework built around a single invariant:

> **One proof, generated once, verifies bytewise-identically on EVM and Solana
> without re-encoding or re-proving.**

- A developer writes a circuit **once** in Rust against the `Circuit` trait.
- The framework produces a client-side prover (browser WASM + native CLI), a
  Solidity verifier contract, and a Rust BPF verifier for Solana.
- All three accept **the same proof bytes**. Public inputs use the same
  values — only byte order differs per target (BE on EVM, LE on Solana).

genshi is a **framework**, not an application. It contains zero references to
notes, pools, nullifiers, bridges, or any domain concept (invariant J5 / J11 —
grep-enforced).

### Target VMs (v1)
- EVM: any BN254-precompile chain (Ethereum, Avalanche, Base, Arbitrum,
  Monad, Polygon)
- Solana: via `sol_alt_bn128_pairing` + `sol_keccak256` syscalls

### First consumers
- **Shroud Pool** — institutional privacy pool (UTXO-style notes)
- **Cross-VM Private Bridge** — one proof burns on chain A, mints on chain B
- Additional: Private Payroll, Private DEX, Institutional Channels

---

## 2. How the framework works

### 2.1 Proving system (locked)

| Layer | Choice |
|---|---|
| Arithmetization | 4-wire PLONKish, custom gates |
| Polynomial commitment | KZG over BN254 |
| In-circuit curve | Grumpkin (native to BN254's scalar field) |
| Pairing curve | BN254 G1/G2 |
| Hash | Poseidon2 (arities t=2,3,4,5; x^5 S-box; 8 full / 56 partial rounds) |
| Transcript (Fiat–Shamir) | Keccak-256 — native opcode on EVM, syscall on Solana |
| Lookup | Plookup-style grand-product argument |
| Trusted setup | Universal KZG (Aztec Powers of Tau) — never per-circuit |

### 2.2 Two-layer separation

```
┌───────────────── Application Layer ─────────────────┐
│ Shroud Pool │ Bridge │ DEX │ Payroll │ … (external) │
└───────────────────────┬─────────────────────────────┘
                        │ depends on genshi-* crates
┌───────────────────────▼─────────────────────────────┐
│                  genshi Framework                   │
│ genshi-core  — constraint system, prover, verifier  │
│ genshi-evm   — Solidity emitter + reusable libs     │
│ genshi-solana — Rust BPF verifier                   │
│ genshi-wasm  — browser helpers + #[wasm_bindgen]    │
│ genshi-cli   — framework tooling binary             │
└─────────────────────────────────────────────────────┘
```

Dependency order: `genshi-core` is the root. Everything else pulls it in.

```
genshi-cli    ──► genshi-evm    ──► genshi-core
genshi-solana ─────────────────────► genshi-core
genshi-wasm   ─────────────────────► genshi-core
```

### 2.3 Load-bearing factoring: `verify_prepare`

`genshi_core::proving::verifier::verify_prepare()` runs transcript replay and
the constraint equation, returning the G1/G2 points needed for pairings. This
single code path runs on native, WASM, and BPF — only the pairing primitive
is swapped:

| Target | Pairing |
|---|---|
| Native / WASM | `ark_bn254::Bn254::pairing` |
| Solana (BPF) | `sol_alt_bn128_pairing` syscall |
| EVM | `ecPairing` precompile (0x08) |

This is invariant **J1**: same code path, different pairing primitive → same
verification decision on identical bytes.

### 2.4 Canonical wire format (ABI, locked)

All byte layouts live in `genshi_core::proving::serialization`:

| Artifact | Size | Encoding |
|---|---|---|
| G1 point | 64 B | x, y as 32 B big-endian |
| G2 point | 128 B | (x1, x0, y1, y0) as 32 B big-endian each |
| Fr (EVM public input) | 32 B | big-endian |
| Fr (Solana public input) | 32 B | little-endian |
| Proof | ~1,216 B | see §5.1 of `Technical_Req.md` |
| VK | 880 B | see §5.2 of `Technical_Req.md` |
| SRS | `4 + 64·n + 256` B | `num_g1_powers` + powers + `[g2_one, g2_tau]` |

Use these helpers only — never hand-roll the encoding:

```rust
use genshi_core::proving::serialization::{
    proof_to_bytes, proof_from_bytes,
    vk_to_bytes, vk_from_bytes,
    public_inputs_to_bytes_le,   // Solana
    public_inputs_to_bytes_be,   // EVM
};
```

### 2.5 Framework invariants (enforced)

| # | Invariant |
|---|---|
| J1 | Same `verify_prepare()` across native/WASM/BPF; only pairing swaps |
| J2 | Canonical proof bytes are the only valid serialization |
| J3 | Keccak transcript everywhere; no alternatives compiled in |
| J4 | Canonical public-input encoders (`public_inputs_to_bytes_be/_le`) |
| J5 | Poseidon2 parameters canonical — matches Solidity `Poseidon2.sol` byte-for-byte |
| J6 | No cross-compilation drift — bit-identical outputs on native/WASM/BPF |
| J7 | SRS from verifiable ceremony (Aztec PoT); custom SRS rejected in production |
| J8 | `genshi-core` compiles to WASM + BPF + native from the same source |
| J9 | Solidity verifier uses only ecAdd/ecMul/ecPairing/modexp — no chain-specific opcodes |
| J10 | Lookup-table soundness: range bypass rejected |
| J11 | Zero application keywords in `genshi/` (grep-enforced) |
| J12 | Every `impl Circuit` that compiles inherits J1–J11 |

---

## 3. The `Circuit` trait — the whole authoring contract

Apps only implement this trait. Everything else (prove, verify, emit-sol,
BPF verify, WASM) is driven generically by the framework.

```rust
pub trait Circuit {
    type Witness;
    type PublicInputs: AsRef<[Fr]>;
    const ID: &'static str;

    fn num_public_inputs() -> usize;
    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        witness: &Self::Witness,
    ) -> Self::PublicInputs;
    fn dummy_witness() -> Self::Witness;
}
```

| Member | Purpose |
|---|---|
| `Witness` | Private+public inputs in native form |
| `PublicInputs` | Public output values, order matches `set_public` calls |
| `ID` | Stable string for SRS/VK bookkeeping |
| `synthesize` | Wire constraints into the builder, return public inputs |
| `dummy_witness` | Zeroed witness whose synthesis has the *same shape* as a real one — used at setup to extract the VK without real data |

### Builder primitives

Available on `UltraCircuitBuilder`:

| Method | Purpose |
|---|---|
| `add_variable(Fr) -> WireRef` | Allocate a witness wire |
| `add / sub / mul` | Field arithmetic |
| `assert_equal(a, b)` | Enforce equality |
| `set_public(wire)` | Mark a wire as a public input |
| `create_add_gate / create_mul_gate` | Raw gates |

Gadgets in `genshi_core::gadgets`:

- `poseidon2_gadget` — in-circuit Poseidon2 (matches `Poseidon2.sol`)
- `merkle` — N-ary Poseidon2 Merkle membership
- `range_proof` — bit-decomposition range checks

### Minimal example

```rust
use ark_bn254::Fr;
use genshi_core::circuit::Circuit;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

pub struct AddCircuit;
pub struct AddWitness { pub a: Fr, pub b: Fr }

impl Circuit for AddCircuit {
    type Witness = AddWitness;
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "myapp.add.v1";

    fn num_public_inputs() -> usize { 1 }

    fn synthesize(b: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
        let a_w = b.add_variable(w.a);
        let b_w = b.add_variable(w.b);
        let c   = b.add(a_w, b_w);
        b.set_public(c);
        [w.a + w.b]
    }

    fn dummy_witness() -> Self::Witness {
        AddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
    }
}
```

### Prove + verify

```rust
use genshi_core::proving::{api, srs::SRS};

let srs = SRS::insecure_for_testing(1024);          // dev only — see §7
let vk  = api::extract_vk::<AddCircuit>(&srs);

let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };
let (proof, _vk, pi) = api::prove::<AddCircuit>(&witness, &srs);
assert!(api::verify::<AddCircuit>(&proof, &vk, &pi, &srs));
```

---

## 4. End-to-end usage

### 4.1 Scaffold a project

```bash
cargo install genshi-cli                    # generic tooling binary
genshi new my-zk-app                        # scaffold a consumer crate
cd my-zk-app
```

Inside the scaffold:
- `src/lib.rs` — write your `Circuit` impls
- `src/bin/genshi.rs` — one-line shim (`fn main() { genshi_cli::run() }`)
  that links your circuits into the per-crate `genshi` binary
- Register each circuit: `genshi_cli::register!(MyCircuit, "my-circuit");`

Now `cargo run --bin genshi -- circuits` lists your circuits.

### 4.2 SRS

```bash
# Dev (insecure — known tau, never deploy)
genshi srs new --max-degree 65536 --output srs.bin

# Production — run your own Powers-of-Tau ceremony
genshi srs ceremony --max-degree 65536 --participants 3 --output srs.bin

genshi srs verify --file srs.bin
```

`max_degree` must be ≥ the largest circuit you intend to prove — it cannot be
retrofitted without re-running the ceremony.

### 4.3 EVM target (Solidity)

```bash
# Extract VK, emit verifier contract — one command
cargo run --bin genshi -- emit-verifier \
  --circuit       transfer \
  --srs           srs.bin \
  --contract-name TransferVerifier \
  --output        contracts/

# Reusable libraries (optional)
genshi emit-poseidon2 --output contracts/library
genshi emit-libs      --output contracts/library   # MerkleTree, NullifierSet, RootHistory
```

Forge config — `via_ir = true` is **mandatory** (locals in `_checkConstraint`
exceed legacy codegen's stack budget):

```toml
# foundry.toml
[profile.default]
src = "contracts"
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 200
via_ir = true
```

```bash
forge build
forge create contracts/TransferVerifier.sol:TransferVerifier \
  --rpc-url $RPC --private-key $KEY
```

Emitted contract exposes exactly one entry point:

```solidity
function verify(bytes calldata proof, uint256[] calldata publicInputs)
    external view returns (bool);
```

- `proof` = exact bytes of `proof_to_bytes(&proof)`.
- `publicInputs` = one `uint256` per `Fr`, big-endian, in the order your
  `synthesize` called `set_public`. Values must be `< P` (BN254 scalar modulus).

Regen rule: if `extract_vk::<C>(&srs)` would return different bytes, re-emit
and redeploy. Wire it into a Makefile/`just` recipe.

Reference costs (Shroud Pool withdraw, 4 public inputs):

| Operation | Gas |
|---:|---:|
| `verify(proof, pi)` accept | **601,513** |
| `verify(proof, wrong_pi)` reject | **228,028** |

### 4.4 Solana target (BPF)

No code generation — one generic program, different VK bytes at runtime.

```toml
# programs/my-app/Cargo.toml
[dependencies]
genshi-core   = { version = "0.1", default-features = false }
genshi-solana = { version = "0.1" }
```

Generate the VK once and `include_bytes!` it:

```rust
pub const SRS_BYTES: &[u8]         = include_bytes!("../../../setup/srs.bin");
pub const TRANSFER_VK_BYTES: &[u8] = include_bytes!("vk_transfer.bin");
```

Verifying instruction:

```rust
use genshi_core::proving::srs::SRS;
use genshi_solana::verify::verify_from_bytes;

let srs = SRS::load_from_bytes(SRS_BYTES);
let ok  = verify_from_bytes(proof_bytes, TRANSFER_VK_BYTES, pi_bytes_le, &srs)?;
```

Public inputs must be concatenated 32-byte **little-endian** Fr elements
(`public_inputs_to_bytes_le`). A full genshi verify does two 2-pair checks
(batch KZG + z-opening) ≈ 560K CU + field arithmetic — well inside the 1.4M CU
budget.

```bash
cargo build-sbf --manifest-path programs/my-app/Cargo.toml
solana program deploy target/deploy/my_app.so \
  --program-id programs/my-app/keypair.json
```

Host-side tests work without `cargo build-sbf` — on native, `pairing_check_2`
falls back to `ark_bn254::Bn254::pairing`.

### 4.5 Browser (WASM)

```bash
wasm-pack build crates/genshi-wasm --target web --release
```

For **verifying only**, use the ready-made `#[wasm_bindgen]` exports in
`genshi-wasm` (`init`, `verifyProof`, `composeProofBlob`, `proofFromBlob`,
`piFromBlob`).

For **proving**, ship your own cdylib wrapping `genshi_wasm::prove_circuit::<C>`:

```rust
// my-app-wasm/src/lib.rs
use wasm_bindgen::prelude::*;
use genshi_wasm::{prove_circuit, install_panic_hook};
use my_app::{MyCircuit, MyWitness};

#[wasm_bindgen(start)]
pub fn start() { install_panic_hook(); }

#[wasm_bindgen]
pub fn prove_my_app(witness_json: &str, srs_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let w: MyWitness = serde_json::from_str(witness_json).map_err(|e| JsError::new(&e.to_string()))?;
    let (blob, _vk) = prove_circuit::<MyCircuit>(&w, srs_bytes).map_err(JsError::new)?;
    Ok(blob)
}
```

### 4.6 The dual-VM loop in one picture

```
    change Circuit impl
            │
            ▼
    api::extract_vk::<C>(&srs)                 (one VK — feeds both targets)
            │
       ┌────┴────────────────────┐
       ▼                         ▼
  emit .sol → forge            refresh vk.bin → cargo build-sbf
  build → forge create         → solana program deploy
       │                         │
       └────────┬────────────────┘
                ▼
       client: api::prove::<C>(&w, &srs) → proof_to_bytes(&proof)
                │
       ┌────────┴────────────────┐
       ▼                         ▼
    EVM: verify(proof,        Solana: instruction
         pi_be_uint256[])            [len | proof | pi_le]
```

Three rules keep this sound:

1. **One SRS across both targets.** Mismatch → guaranteed failure.
2. **Public-input order is canonical** — whatever order `synthesize` called
   `set_public`. Pin it with `IDX_*` constants on your public-inputs struct.
3. **Endianness is per-target** — `_bytes_be` for EVM, `_bytes_le` for Solana.

---

## 5. CLI reference

All circuit-aware commands take `--circuit <name>` where `<name>` is the literal
string passed to `genshi_cli::register!`.

### 5.1 Install

```bash
cargo install genshi-cli           # generic (no circuits linked)
genshi --help
# inside a scaffolded crate:
cargo run --bin genshi -- <cmd>    # registry linked in
```

### 5.2 Project scaffolding

| Command | Description |
|---|---|
| `cargo run --bin genshi -- new my-app` | Scaffold a new genshi project |
| `cargo run --bin genshi -- new my-app --source path:/path/to/genshi` | Scaffold using a local genshi checkout |
| `cargo run --bin genshi -- new my-app --source git:https://github.com/shroud-network/genshi#rev=main` | Pin a git revision |

### 5.3 Circuit registry

| Command | Description |
|---|---|
| `cargo run --bin genshi -- circuits` | List all registered circuits |

### 5.4 SRS generation

| Command | Description |
|---|---|
| `cargo run --bin genshi -- srs new --max-degree 65536 --output srs.bin` | **Dev only** — insecure SRS with known tau (instant, never deploy) |
| `cargo run --bin genshi -- srs ceremony --max-degree 65536 --participants 3 --output srs.bin` | **Production** — Powers-of-Tau ceremony with OS entropy |
| `cargo run --bin genshi -- srs import --input ceremony.ptau --max-degree 65536 --output srs.bin` | **Production** — import from external `.ptau` file |
| `cargo run --bin genshi -- srs verify --file srs.bin` | Verify SRS pairing consistency |

> **Insecure vs Production:** `srs new` uses a hardcoded tau — anyone can
> forge proofs. `srs ceremony` and `srs import` use real entropy with 1-of-N
> trust — if even one participant honestly destroys their secret, forgery is
> cryptographically impossible. **Never deploy with `srs new`.**

### 5.5 Witness generation

| Command | Description |
|---|---|
| `cargo run --bin genshi -- gen-witness --circuit transfer --output witness.json` | Generate witness JSON for `transfer` |
| `cargo run --bin genshi -- gen-witness --circuit withdraw --output witness.json` | Generate witness JSON for `withdraw` |
| `cargo run --bin genshi -- gen-witness --circuit transfer` | Print witness JSON to stdout |

The generated witness satisfies every circuit constraint with default values.
Edit the JSON to substitute your own data.

### 5.6 Proving

| Command | Description |
|---|---|
| `cargo run --bin genshi -- prove --circuit transfer --witness witness.json --srs srs.bin --output out/` | Generate a proof from a witness |

Outputs: `out/proof.bin`, `out/vk.bin`, `out/public_inputs.bin`.

### 5.7 Verification

| Command | Description |
|---|---|
| `cargo run --bin genshi -- verify --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin` | Verify a proof natively |
| `cargo run --bin genshi -- verify --circuit transfer --srs srs.bin --proof proof.bin --public-inputs public.json` | Verify by re-deriving the VK from a registered circuit |

### 5.8 Verification-key extraction

| Command | Description |
|---|---|
| `cargo run --bin genshi -- extract-vk --circuit transfer --srs srs.bin --output transfer.vk` | Extract VK for a circuit |

### 5.9 Solidity emission (EVM)

| Command | Description |
|---|---|
| `cargo run --bin genshi -- emit-verifier --circuit transfer --srs srs.bin --output contracts/ --contract-name TransferVerifier` | Emit verifier contract for a circuit (preferred path) |
| `cargo run --bin genshi -- emit-evm --vk transfer.vk --srs srs.bin --output contracts/` | Emit verifier from a standalone VK file (escape hatch) |
| `cargo run --bin genshi -- emit-poseidon2 --output contracts/` | Emit `Poseidon2.sol` library |
| `cargo run --bin genshi -- emit-libs --output contracts/` | Emit all reusable libraries (`MerkleTree`, `NullifierSet`, `RootHistory`, …) |

### 5.10 Artifact inspection

| Command | Description |
|---|---|
| `cargo run --bin genshi -- inspect --kind proof --file out/proof.bin` | Validate a proof file |
| `cargo run --bin genshi -- inspect --kind vk --file out/vk.bin` | Validate a VK file |

### 5.11 Production flow — end to end

```bash
cargo run --bin genshi -- srs ceremony      --max-degree 65536 --participants 3 --output srs.bin
cargo run --bin genshi -- srs verify        --file srs.bin
cargo run --bin genshi -- gen-witness       --circuit transfer --output witness.json
cargo run --bin genshi -- prove             --circuit transfer --witness witness.json --srs srs.bin --output out/
cargo run --bin genshi -- verify            --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin
cargo run --bin genshi -- emit-verifier     --circuit transfer --srs srs.bin --output contracts/ --contract-name TransferVerifier
cargo run --bin genshi -- emit-libs         --output contracts/
```

### 5.12 End-to-end regen loop (whenever a circuit changes)

```bash
# 1. Rebuild the per-crate binary so the registry picks up edits
cargo build --bin genshi

# 2. Re-extract VK + re-emit the Solidity verifier
cargo run --bin genshi -- emit-verifier --circuit transfer --srs srs.bin \
  --output contracts/ --contract-name TransferVerifier

# 3. Rebuild Solidity
forge build --via-ir && forge test --via-ir

# 4. Rebuild the Solana program
cargo build-sbf --manifest-path programs/my-app/Cargo.toml

# 5. Rebuild the browser bundle
wasm-pack build crates/genshi-wasm --target web --release
```

---

## 6. Testing

```bash
cargo test --workspace                # 242 tests pass
cargo test -p genshi-core
cargo test -p genshi-evm
cargo test -p genshi-solana
cargo test -p genshi-wasm
```

End-to-end Forge test (real Rust proof → real Solidity verifier):

```bash
cargo test -p genshi-evm --lib -- --ignored dump_for_forge
cd /tmp/genshi_fcheck
git init -q && forge install foundry-rs/forge-std
forge test --match-contract genshiVerifierTest -vvv
# PASS testRejectsWrongPublicInput (gas 136,025)
# PASS testVerifyRustProof         (gas 511,162)
```

---

## 7. SRS / trusted setup

- `SRS::insecure_for_testing(max_degree)` uses a hardcoded tau — **anyone can
  forge proofs**. Never deploy.
- Production: `genshi srs ceremony` or `genshi srs import` (Aztec PoT).
- 1-of-N trust: if *any* participant honestly destroys their tau share, forgery
  is cryptographically infeasible.
- `max_degree` must be ≥ your largest circuit's gate count, rounded up to a
  power of two. It cannot be grown later without re-running the ceremony.
- SRS + VK are **not secrets** — publish them with your code.

---

## 8. Publishing to crates.io

### 8.1 Dependency order (mandatory)

```
genshi-core ──► genshi-evm ──► genshi-cli
genshi-core ──► genshi-solana
genshi-core ──► genshi-wasm
```

crates.io rejects any crate whose published deps don't yet exist. Publish
roots first. `genshi-core` must land before anything else.

### 8.2 One-time metadata check

```bash
cargo login                    # paste your crates.io API token
cargo metadata --no-deps --format-version 1 \
  | jq '.packages[] | {name, description, license, repository}'
```

Each crate must have in its `[package]` table (inherited from
`[workspace.package]` or set locally):
- `description`, `license`, `repository`, `homepage`, `readme`, `keywords`,
  `categories`
- A `README.md` (all five crates already have one)
- `LICENSE-MIT` + `LICENSE-APACHE` at the workspace root (already present)

Path deps must also carry a `version`:

```toml
# crates/genshi-evm/Cargo.toml
[dependencies]
genshi-core = { path = "../genshi-core", version = "0.1.0", default-features = false }
```

The workspace `Cargo.toml` already pairs `path` + `version` on every
`genshi-*` entry:

```toml
genshi-core   = { path = "crates/genshi-core",   version = "0.1.0" }
genshi-evm    = { path = "crates/genshi-evm",    version = "0.1.0" }
genshi-solana = { path = "crates/genshi-solana", version = "0.1.0" }
genshi-wasm   = { path = "crates/genshi-wasm",   version = "0.1.0" }
```

### 8.3 Dry run in dependency order

```bash
cargo publish -p genshi-core    --dry-run
cargo publish -p genshi-evm     --dry-run
cargo publish -p genshi-solana  --dry-run
cargo publish -p genshi-wasm    --dry-run
cargo publish -p genshi-cli     --dry-run
```

Resolve any warnings about missing metadata, oversized tarballs, or unresolved
deps before going live.

> **Gotcha — dry-run fails for dependents before the root is published.**
> `cargo publish --dry-run` still resolves `version = "0.1.0"` against the
> crates.io index. Because path-deps carry a real version requirement, the
> dry-runs for `genshi-evm`, `genshi-solana`, `genshi-wasm`, `genshi-cli`
> will fail with:
>
> ```
> error: failed to prepare local package for uploading
> Caused by: no matching package named `genshi-core` found
>            location searched: crates.io index
> ```
>
> This is **not** a real failure — it just means the root crate isn't on the
> registry yet. Workaround: dry-run **only** `genshi-core` first, publish it
> for real, wait ~60s for the index to refresh, then dry-run (or directly
> publish) the four dependents. See §8.4 for the full ordered flow.
>
> Alternative: `cargo install cargo-workspaces && cargo workspaces publish
> --from-git` handles the wait-for-index step automatically.

### 8.4 Publish for real

```bash
cargo publish -p genshi-core
# wait ~30s for the registry index to update
cargo publish -p genshi-evm
cargo publish -p genshi-solana
cargo publish -p genshi-wasm
cargo publish -p genshi-cli
```

### 8.5 Recovering from a failed mid-publish

Published versions on crates.io are **immutable** — you can yank but never
overwrite.

If a publish fails halfway:

1. Fix the issue.
2. Bump the version of the failed crate **and every crate that depends on it**.
3. Resume from the failed crate.

Because the workspace uses `version.workspace = true`, a single edit in
`genshi/Cargo.toml` bumps all crates in lockstep:

```toml
[workspace.package]
version = "0.1.1"
```

Commit, tag, and re-publish in dependency order.

### 8.6 Consuming from crates.io

Once published, consumers add only the targets they actually deploy to:

```toml
[dependencies]
genshi-core   = "0.1"
genshi-evm    = "0.1"   # if emitting a Solidity verifier
genshi-solana = "0.1"   # if shipping a Solana program
genshi-wasm   = "0.1"   # if proving/verifying in the browser
```

And install the binary:

```bash
cargo install genshi-cli
genshi new my-zk-app
```

### 8.7 How the docs actually land in front of external devs

Publishing to crates.io gives genshi **three distribution surfaces for
documentation**. All three must exist or external devs have no way to learn
the framework.

**1. The crates.io crate page** (`https://crates.io/crates/genshi-core`, etc.)

Renders the crate's `README.md` verbatim. This is the landing page — the
first thing a dev sees after `cargo search genshi`. Every crate in the
workspace already sets `readme = "README.md"` in its `Cargo.toml`, and all
five `crates/*/README.md` files exist. Ship these as the elevator pitch:
what the crate is, a minimal example, link to the full docs.

**2. docs.rs** (`https://docs.rs/genshi-core`, etc.)

Auto-built from the source on every publish — no action needed beyond
publishing. Renders all `///` doc-comments into a browsable API reference.
To make docs.rs useful:

- Add crate-level docs in `src/lib.rs`:

  ```rust
  //! # genshi-core
  //!
  //! Core cryptographic library for the genshi dual-VM ZK framework.
  //!
  //! See the [authoring guide](https://github.com/shroud-network/genshi/blob/main/GUIDE.md)
  //! and [consolidated docs](https://github.com/shroud-network/genshi/blob/main/DOCS.md).
  #![cfg_attr(not(feature = "std"), no_std)]
  ```

- Doc every public item (`pub fn`, `pub struct`, `pub trait`). Rustdoc lints
  (`#![deny(missing_docs)]`) catch gaps.

- Configure `[package.metadata.docs.rs]` so docs.rs builds with the same
  features the crate actually ships with — otherwise conditional items
  (e.g. the `wasm_bindgen` surface in `genshi-wasm`) disappear from the
  reference:

  ```toml
  # crates/genshi-core/Cargo.toml
  [package.metadata.docs.rs]
  all-features = true
  rustdoc-args = ["--cfg", "docsrs"]
  ```

- Verify locally before publishing:

  ```bash
  cargo doc --workspace --all-features --no-deps --open
  ```

**3. The GitHub repo** (linked via `repository = "..."` in every
`Cargo.toml`).

The crates.io page prominently links to it. External devs click through for
the long-form guides — `README.md` (overview), `DOCS.md` (this file), and
`GUIDE.md` (full walkthrough). These must live on the default branch of the
repo referenced in the manifest, or the link is broken.

### 8.8 Bake the README into the docs.rs landing page

docs.rs uses the crate root's doc-comment as the front page. To show the
README there too without duplicating content, add this at the top of each
crate's `src/lib.rs`:

```rust
#![doc = include_str!("../README.md")]
```

Now `https://docs.rs/genshi-core` opens with the same content as
`https://crates.io/crates/genshi-core` — a single source of truth, rendered
on both surfaces.

### 8.9 Publishing checklist (tick before `cargo publish`)

- [ ] `cargo test --workspace` — 242 tests pass
- [ ] `cargo doc --workspace --all-features --no-deps` — no rustdoc warnings
- [ ] `cargo publish --dry-run` succeeds for every crate in dep order
- [ ] Each `crates/*/README.md` renders correctly on GitHub preview
- [ ] `CHANGELOG.md` entry exists for the version being released
- [ ] Git tag `v0.1.0` pushed (`git tag v0.1.0 && git push --tags`)
- [ ] `repository` + `homepage` URLs in every `Cargo.toml` resolve to 200

---

## 9. Source-of-truth map

| Question | File |
|---|---|
| `Circuit` trait | `crates/genshi-core/src/circuit.rs` |
| Prove / verify / extract-vk | `crates/genshi-core/src/proving/api.rs` |
| Builder gates | `crates/genshi-core/src/arithmetization/ultra_circuit_builder.rs` |
| Canonical byte format | `crates/genshi-core/src/proving/serialization.rs` |
| Fiat–Shamir transcript | `crates/genshi-core/src/proving/transcript.rs` |
| Poseidon2 params | `crates/genshi-core/src/crypto/poseidon2.rs` |
| Solidity emitter | `crates/genshi-evm/src/solidity_emitter.rs` |
| Reusable `.sol` libs | `crates/genshi-evm/contracts/library/` |
| BPF pairing path | `crates/genshi-solana/src/crypto/mod.rs` |
| WASM exports | `crates/genshi-wasm/src/lib.rs` (`wasm` module) |
| CLI | `crates/genshi-cli/src/lib.rs` |

---

## 10. Roadmap status (April 2026)

| Phase | Status |
|---|---|
| 0 — pre-genshi foundation | ✅ complete (159 tests under old `shroud-honk` name) |
| 1 — genshi / app workspace split | 🔨 in progress |
| 2 — `Circuit` trait + generic prover API | 📋 planned |
| 3 — custom gates (Poseidon2, elliptic, plookup) | 📋 planned |
| 4 — Shroud Pool v1 on genshi | 📋 planned |
| 5 — cross-VM bridge (second consumer) | 📋 future |
| 6 — v1 crates.io release | 📋 future |
| 7 — audit + mainnet | 📋 future |

Current test count: **242 passing** across the workspace.

Out of scope for v1: ACIR compat, GPU MSM, folding schemes, additional VM
targets (Sui/Aptos/NEAR), IPA, Zeromorph proof compression — all deferred
until after at least two independent external consumers ship on v1.
