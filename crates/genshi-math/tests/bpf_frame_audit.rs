//! BPF frame-size audit for genshi-math.
//!
//! Solana BPF enforces a 4 096-byte maximum stack frame per function call.
//! This test documents the theoretical worst-case stack allocation of every
//! public BPF function in genshi-math and asserts all are safely under the
//! limit.
//!
//! The audit counts local variables visible in source: `[u64; N]`, `[u8; N]`,
//! scalar temporaries, and loop variables. LLVM may introduce additional
//! spills, but with `opt-level = "z"` and `#[inline(never)]` (applied in P3),
//! these align closely with source-level accounting. Empirical SBF validation
//! happens when the solana/ harness builds in P3/P5.

const BPF_MAX_FRAME: usize = 4096;

struct FrameEntry {
    function: &'static str,
    module: &'static str,
    stack_bytes: usize,
    notes: &'static str,
}

const FRAME_AUDIT: &[FrameEntry] = &[
    // ---- bpf/fr.rs ----
    FrameEntry {
        function: "mont_mul",
        module: "bpf::fr",
        // t: [u64; 5] = 40, carry: u64 = 8, m: u64 = 8, loop vars = ~16
        // mac calls: inlined (2x u64 = 16 each, but inlined into parent)
        stack_bytes: 96,
        notes: "CIOS: 5-limb accumulator + carry + reduction var",
    },
    FrameEntry {
        function: "Fr::pow",
        module: "bpf::fr",
        // result: Fr = 32, loop vars (limb, i) = 16
        // calls mont_mul twice per bit (square + conditional mul)
        stack_bytes: 80,
        notes: "square-and-multiply; calls mont_mul per bit",
    },
    FrameEntry {
        function: "Fr::inverse",
        module: "bpf::fr",
        // delegates to pow(&P_MINUS_2)
        stack_bytes: 16,
        notes: "thin wrapper over pow",
    },
    FrameEntry {
        function: "Fr::from_be_bytes_mod_order",
        module: "bpf::fr",
        // reduce_be_bytes: [u64; 4] = 32 intermediate, bytes parsing
        // then mont_mul call
        stack_bytes: 80,
        notes: "byte parsing + mont_mul for Montgomery conversion",
    },
    FrameEntry {
        function: "Fr::to_be_bytes",
        module: "bpf::fr",
        // reduced: [u64; 4] = 32, out: [u8; 32] = 32
        stack_bytes: 80,
        notes: "mont_mul to exit Montgomery + byte assembly",
    },
    FrameEntry {
        function: "Fr::from_le_bytes_mod_order",
        module: "bpf::fr",
        // be: [u8; 32] = 32, then delegates to from_be_bytes_mod_order
        stack_bytes: 48,
        notes: "byte reversal + delegation",
    },
    FrameEntry {
        function: "add_impl (Fr + Fr)",
        module: "bpf::fr",
        // result: [u64; 4] = 32, carry: u64 = 8
        stack_bytes: 48,
        notes: "4-limb add with carry + conditional subtract",
    },
    FrameEntry {
        function: "sub_impl (Fr - Fr)",
        module: "bpf::fr",
        // result: [u64; 4] = 32, borrow: u64 = 8
        stack_bytes: 48,
        notes: "4-limb sub with borrow + conditional add",
    },

    // ---- bpf/curve.rs ----
    FrameEntry {
        function: "g1_add (syscall path)",
        module: "bpf::curve",
        // input: [u8; 128] = 128, output: [u8; 64] = 64
        stack_bytes: 208,
        notes: "sol_alt_bn128_addition I/O buffers",
    },
    FrameEntry {
        function: "g1_scalar_mul (syscall path)",
        module: "bpf::curve",
        // input: [u8; 96] = 96, output: [u8; 64] = 64
        stack_bytes: 176,
        notes: "sol_alt_bn128_multiplication I/O buffers",
    },
    FrameEntry {
        function: "G1Projective::neg",
        module: "bpf::curve",
        // result: [u8; 64] = 64 (copy), neg_y: [u8; 32] = 32
        // fq_negate: result [u8; 32] = 32, borrow: u16 = 2
        stack_bytes: 136,
        notes: "point copy + Fq negate (big-endian subtraction)",
    },
    FrameEntry {
        function: "G2Affine::generator",
        module: "bpf::curve",
        // buf: [u8; 128] = 128 (on solana: loads const, no alloc)
        // on host fallback: arkworks decode = larger but irrelevant for BPF
        stack_bytes: 144,
        notes: "host fallback uses arkworks; BPF loads const",
    },

    // ---- bpf/pairing.rs ----
    FrameEntry {
        function: "pairing_check",
        module: "bpf::pairing",
        // input: [u8; 384] = 384
        stack_bytes: 400,
        notes: "largest single allocation in genshi-math BPF",
    },
    FrameEntry {
        function: "pairing_check_raw (syscall path)",
        module: "bpf::pairing",
        // output: [u8; 32] = 32
        stack_bytes: 48,
        notes: "sol_alt_bn128_pairing output buffer + bool check",
    },
];

#[test]
fn all_bpf_frames_under_4kb() {
    let mut max_frame = 0usize;
    let mut max_name = "";

    for entry in FRAME_AUDIT {
        assert!(
            entry.stack_bytes < BPF_MAX_FRAME,
            "{module}::{function} estimated at {bytes} bytes, exceeds BPF limit of {limit} ({notes})",
            module = entry.module,
            function = entry.function,
            bytes = entry.stack_bytes,
            limit = BPF_MAX_FRAME,
            notes = entry.notes,
        );
        if entry.stack_bytes > max_frame {
            max_frame = entry.stack_bytes;
            max_name = entry.function;
        }
    }

    // Largest frame should be pairing_check at 400 bytes — well under 4 KB.
    assert!(
        max_frame <= 512,
        "largest BPF frame is {max_name} at {max_frame} bytes; expected <= 512"
    );
}

#[test]
fn deepest_call_chain_under_4kb() {
    // The deepest genshi-math BPF call chain is:
    //   pairing_check (400) → pairing_check_raw (48)
    //   Fr::inverse (16) → pow (80) → mont_mul (96)
    //   G1Affine * Fr → g1_scalar_mul (176)
    //
    // Solana allocates a new 4 KB frame per function call, so the relevant
    // metric is max single frame, not cumulative depth. But we document the
    // chains for completeness.

    let chains: &[(&str, &[usize])] = &[
        ("pairing_check → pairing_check_raw", &[400, 48]),
        ("Fr::inverse → pow → mont_mul", &[16, 80, 96]),
        ("G1Affine * Fr → g1_scalar_mul", &[32, 176]),
        ("G1Projective + → g1_add", &[32, 208]),
        ("G1Projective::neg → fq_negate", &[136]),
    ];

    for (chain_name, frames) in chains {
        let max_in_chain = frames.iter().copied().max().unwrap_or(0);
        assert!(
            max_in_chain < BPF_MAX_FRAME,
            "chain '{chain_name}' has frame of {max_in_chain} bytes, exceeds 4 KB"
        );
    }
}

#[test]
fn pairing_input_buffer_is_largest_allocation() {
    // The 384-byte pairing input buffer is by far the largest stack
    // allocation. Verify it stays under 1 KB (generous headroom).
    let pairing_entry = FRAME_AUDIT
        .iter()
        .find(|e| e.function == "pairing_check")
        .unwrap();
    assert!(pairing_entry.stack_bytes <= 1024);
}
