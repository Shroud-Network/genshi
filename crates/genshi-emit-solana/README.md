# genshi-emit-solana

Anchor program codegen for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Takes verification keys produced by [`genshi-core`](https://crates.io/crates/genshi-core) and emits a self-contained Anchor program that verifies proofs on Solana via `sol_alt_bn128_*` syscalls. The emitted program has **zero runtime dependency on `genshi-core`** — all it links against is [`genshi-math`](https://crates.io/crates/genshi-math) with the `bpf` feature and `anchor-lang`.

Per-VK codegen sidesteps both BPF pitfalls of the earlier runtime-library approach:

- The prover path is never compiled into the Solana binary — the emitter only emits verifier-side code.
- Verification keys are hardcoded as byte constants, so there's no generic deserialization on the on-chain path and the verifier stack stays under the 4 KB BPF limit.

A single emitted program can expose multiple circuits (e.g. `withdraw`, `transfer`) — one instruction per circuit — with a shared buffer-PDA streaming path for proof and public-input data that exceeds the 1232-byte Solana transaction limit.

Typically consumed via the `emit solana` subcommand in [`genshi-cli`](https://crates.io/crates/genshi-cli) rather than used directly.

## Example

```rust
use genshi_core::proving::api;
use genshi_core::proving::srs::SRS;
use genshi_core::proving::serialization::vk_to_bytes;
use genshi_emit_solana::{emit, EmitConfig};

let srs = SRS::insecure_for_testing(65536);
let vk_withdraw = api::extract_vk::<WithdrawCircuit>(&srs);

let mut cfg = EmitConfig::new("shroud-verifier", "out/shroud-verifier");
cfg.add_circuit("withdraw", vk_to_bytes(&vk_withdraw));
emit(&cfg).expect("codegen failed");
```

The resulting directory is a complete Anchor workspace — `anchor build` produces a `.so` deployable to any Solana cluster.

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
