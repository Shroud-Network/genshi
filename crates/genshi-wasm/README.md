# genshi-wasm

Browser WASM helpers for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Provides JavaScript-facing bindings for in-browser proving and serialization so web applications can generate genshi proofs client-side without a backend prover.

This crate is designed to be wrapped by an application-specific `cdylib` that exposes the app's own circuits. It ships with:

- Serialization helpers for proofs, public inputs, and verification keys
- Panic hook wiring for useful browser console errors
- `getrandom` configured for the `js` feature (so arkworks randomness works in the browser)

Typically built with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```bash
wasm-pack build --target web
```

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
