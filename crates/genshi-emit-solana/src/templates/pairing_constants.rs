use genshi_core::proving::srs::SRS;
use genshi_math::G2Affine;
use std::fmt::Write;

pub fn generate(srs: &SRS) -> String {
    let mut out = String::new();
    writeln!(out, "use genshi_math::G2Affine;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "pub fn load_g2() -> G2Affine {{").unwrap();
    writeln!(out, "    G2Affine::from_raw({})", g2_literal(&srs.g2)).unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "pub fn load_g2_tau() -> G2Affine {{").unwrap();
    writeln!(out, "    G2Affine::from_raw({})", g2_literal(&srs.g2_tau)).unwrap();
    writeln!(out, "}}").unwrap();
    out
}

fn g2_literal(point: &G2Affine) -> String {
    let bytes = point.to_uncompressed_bytes();
    byte_array_literal(&bytes)
}

fn byte_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        if i % 16 == 0 && i > 0 {
            out.push_str("\n        ");
        }
        write!(out, "0x{b:02x}").unwrap();
    }
    out.push(']');
    out
}
