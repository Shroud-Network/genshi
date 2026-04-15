# genshi-cli

Circuit-aware command-line tool for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Provides a circom-style CLI on top of genshi: scaffold an app, generate an SRS, register your circuits via a macro, emit Solidity/Solana verifiers, and run the full `gen-witness → prove → verify` loop from the shell.

## Install

```bash
cargo install genshi-cli
```

## Scaffold a new app

```bash
genshi new myApp
cd myApp
cargo run --bin genshi -- circuits
```

`genshi new` generates a Cargo crate with a sample `AddCircuit`, a `src/bin/genshi.rs` one-liner that calls `genshi_cli::run()`, and a circuits directory ready for more. Cargo auto-discovers the `genshi` binary so no extra `[[bin]]` entry is needed.

## Register your own circuit

```rust
use genshi_cli::Circuit;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use ark_bn254::Fr;
use serde::{Serialize, Deserialize};

pub struct MyCircuit;

#[derive(Serialize, Deserialize)]
pub struct MyWitness { pub x: u64 }

impl Circuit for MyCircuit { /* ... */ }

genshi_cli::register!(MyCircuit, "my-circuit");
```

The `register!` macro uses the `inventory` crate to place the circuit into a linker-collected slice at compile time. `genshi-cli` enumerates every registered circuit at runtime — no explicit registration list required in `main`.

## Commands

| Command | Purpose |
|---------|---------|
| `genshi new <name>` | Scaffold a new application crate |
| `genshi srs new` | Insecure SRS for testing |
| `genshi srs ceremony` | Powers-of-tau ceremony (production) |
| `genshi srs import` | Import an existing `.ptau` file |
| `genshi srs verify` | Pairing-check an SRS file |
| `genshi circuits` | List registered circuits |
| `genshi gen-witness` | Produce a provable witness JSON |
| `genshi prove` | Generate a proof from a witness |
| `genshi verify` | Verify a proof natively |
| `genshi extract-vk` | Export a verification key |
| `genshi emit-verifier` | Emit a Solidity verifier contract |
| `genshi emit-libs` | Emit reusable Solidity libraries |
| `genshi emit-poseidon2` | Emit just the Poseidon2 library |
| `genshi inspect` | Dump a proof/VK summary |

See the full [GUIDE.md](https://github.com/shroud-network/genshi/blob/main/GUIDE.md) for detailed documentation.

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
