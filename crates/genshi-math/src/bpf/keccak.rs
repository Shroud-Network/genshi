//! Keccak-256 hasher for the BPF backend.
//!
//! On a real Solana BPF target this routes through the `sol_keccak256`
//! syscall — `85 + n` CU per call, where `n` is the input length in bytes.
//! That is roughly 100× cheaper than running `tiny-keccak` in pure BPF Rust
//! (24 rounds of 64-bit rotates compile to ~8–15K CU per permutation).
//!
//! Off-target builds (host tests, property tests) fall back to `tiny-keccak`
//! so the backend still works under `cargo test` without a Solana VM.
//!
//! The syscall takes an array of fat-pointer descriptors (`SolBytes`) so
//! callers can hash a concatenation of byte slices in one call without
//! building a temporary `Vec`. That matches how Fiat-Shamir transcripts
//! absorb: label + data, repeatedly, before squeezing.

#[cfg(target_os = "solana")]
mod syscall {
    /// Fat-pointer view of a byte slice, matching Solana's `SolBytes` ABI.
    #[repr(C)]
    pub(super) struct SolBytes {
        pub ptr: *const u8,
        pub len: u64,
    }

    solana_define_syscall::define_syscall!(
        fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64
    );

    pub use sol_keccak256 as raw;
}

/// Keccak-256 of the concatenation of `parts`.
///
/// Returns the 32-byte digest. One syscall on BPF; one-shot `tiny-keccak`
/// hasher off-target.
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        let descriptors: alloc::vec::Vec<syscall::SolBytes> = parts
            .iter()
            .map(|p| syscall::SolBytes {
                ptr: p.as_ptr(),
                len: p.len() as u64,
            })
            .collect();
        let mut out = [0u8; 32];
        unsafe {
            syscall::raw(
                descriptors.as_ptr() as *const u8,
                descriptors.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }
    #[cfg(all(not(target_os = "solana"), any(feature = "host-test", feature = "native")))]
    {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        for p in parts {
            k.update(p);
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }
    #[cfg(all(not(target_os = "solana"), not(feature = "host-test"), not(feature = "native")))]
    {
        // Pure-BPF build run off-target without the test fallback — should
        // never happen in practice, but fail loudly rather than returning zeros.
        let _ = parts;
        panic!("genshi-math bpf backend: keccak256 called off-target without `host-test` feature");
    }
}

extern crate alloc;
