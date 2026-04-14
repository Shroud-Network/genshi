//! The `genshi` binary that ships with `genshi-cli`.
//!
//! This binary contains no application circuits, so `genshi circuits list`
//! will report an empty registry — only the circuit-agnostic subcommands
//! (`srs new`, `emit-evm`, `emit-poseidon2`, `emit-libs`, `inspect`, and
//! `verify`) are useful from here.
//!
//! Downstream applications that want a circuit-aware CLI drop a file with
//! the same single-line content into their own crate at `src/bin/genshi.rs`,
//! register their circuits via [`genshi_cli::register!`], and inherit the
//! same command set *plus* `circuits list`, `extract-vk`, and
//! `emit-verifier`.

fn main() -> std::process::ExitCode {
    genshi_cli::run()
}
