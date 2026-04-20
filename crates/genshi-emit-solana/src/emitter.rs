use std::fs;
use std::path::Path;

use genshi_core::proving::serialization::vk_from_bytes;
use genshi_core::proving::srs::SRS;
use genshi_core::proving::types::VerificationKey;

use crate::config::EmitConfig;
use crate::templates;

const VERIFIER_SRC: &str = include_str!("../assets/verifier.rs");
const TRANSCRIPT_SRC: &str = include_str!("../assets/transcript.rs");
const TYPES_SRC: &str = include_str!("../assets/types.rs");

pub fn emit_program(config: &EmitConfig, srs: &SRS) -> Result<(), EmitError> {
    if config.circuits.is_empty() {
        return Err(EmitError::NoCircuits);
    }

    let src_dir = config.out_dir.join("src");
    fs::create_dir_all(&src_dir)?;

    let circuits: Vec<(String, VerificationKey)> = config
        .circuits
        .iter()
        .map(|c| {
            let vk = vk_from_bytes(&c.vk_bytes)
                .map_err(|_| EmitError::InvalidVk(c.name.clone()))?;
            Ok((c.name.clone(), vk))
        })
        .collect::<Result<_, EmitError>>()?;

    write_file(&config.out_dir.join("Cargo.toml"), &templates::cargo_toml::generate(config))?;
    write_file(&config.out_dir.join("Xargo.toml"), &templates::xargo_toml::generate())?;

    write_file(&src_dir.join("lib.rs"), &templates::lib_rs::generate(config))?;
    write_file(&src_dir.join("verifier.rs"), &rewrite_verifier_imports(VERIFIER_SRC))?;
    write_file(&src_dir.join("transcript.rs"), &rewrite_transcript_imports(TRANSCRIPT_SRC))?;
    write_file(&src_dir.join("types.rs"), &rewrite_types(TYPES_SRC))?;
    write_file(&src_dir.join("srs.rs"), &generate_srs_stub())?;
    write_file(&src_dir.join("vk_constants.rs"), &templates::vk_constants::generate(&circuits))?;
    write_file(&src_dir.join("pairing_constants.rs"), &templates::pairing_constants::generate(srs))?;

    if config.emit_anchor_toml {
        write_file(&config.out_dir.join("Anchor.toml"), &generate_anchor_toml(config))?;
    }

    Ok(())
}

fn write_file(path: &Path, content: &str) -> Result<(), EmitError> {
    fs::write(path, content)?;
    Ok(())
}

fn rewrite_verifier_imports(src: &str) -> String {
    let mut out = String::new();
    let mut in_test = false;
    let mut brace_depth = 0u32;

    for line in src.lines() {
        if line.starts_with("#[cfg(") && line.contains("test") {
            in_test = true;
            brace_depth = 0;
            continue;
        }
        if in_test {
            for ch in line.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    if brace_depth == 0 {
                        in_test = false;
                        continue;
                    }
                    brace_depth -= 1;
                }
            }
            if in_test || brace_depth == 0 {
                continue;
            }
        }

        if line.trim() == "use alloc::vec::Vec;"
            || line.trim() == "use alloc::boxed::Box;"
        {
            continue;
        }
        let rewritten = line
            .replace("use super::types::", "use crate::types::")
            .replace("use super::srs::", "use crate::srs::")
            .replace("use super::transcript::", "use crate::transcript::")
            .replace("use crate::proving::types::", "use crate::types::")
            .replace("use crate::proving::srs::", "use crate::srs::")
            .replace("use crate::proving::transcript::", "use crate::transcript::")
            .replace("alloc::vec::Vec", "Vec")
            .replace("alloc::boxed::Box", "Box")
            .replace("alloc::vec!", "vec!");
        out.push_str(&rewritten);
        out.push('\n');
    }
    out
}

fn rewrite_transcript_imports(src: &str) -> String {
    let mut out = String::new();
    let mut in_test = false;
    let mut brace_depth = 0u32;

    for line in src.lines() {
        if line.starts_with("#[cfg(") && line.contains("test") {
            in_test = true;
            brace_depth = 0;
            continue;
        }
        if in_test {
            for ch in line.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    if brace_depth == 0 {
                        in_test = false;
                        continue;
                    }
                    brace_depth -= 1;
                }
            }
            if in_test || brace_depth == 0 {
                continue;
            }
        }

        if line.trim() == "use alloc::vec::Vec;"
            || line.trim() == "use alloc::boxed::Box;"
        {
            continue;
        }
        let rewritten = line
            .replace("alloc::vec::Vec", "Vec")
            .replace("alloc::boxed::Box", "Box")
            .replace("alloc::vec!", "vec!");
        out.push_str(&rewritten);
        out.push('\n');
    }
    out
}

fn rewrite_types(src: &str) -> String {
    let mut out = String::new();

    for line in src.lines() {
        if line.trim() == "use alloc::vec::Vec;"
            || line.trim() == "use alloc::boxed::Box;"
        {
            continue;
        }
        let rewritten = line
            .replace("alloc::vec::Vec", "Vec")
            .replace("alloc::boxed::Box", "Box")
            .replace("alloc::vec!", "vec!");
        out.push_str(&rewritten);
        out.push('\n');
    }

    out.push_str("\n");
    out.push_str(DESERIALIZE_PROOF_FN);
    out
}

fn generate_srs_stub() -> String {
    r#"use genshi_math::G2Affine;

pub struct SRS {
    pub g2: G2Affine,
    pub g2_tau: G2Affine,
}
"#
    .to_string()
}

fn generate_anchor_toml(config: &EmitConfig) -> String {
    let name = &config.program_name;
    format!(
        r#"[toolchain]

[features]
seeds = false
skip-lint = false

[programs.localnet]
{name} = "11111111111111111111111111111112"

[registry]
url = "https://api.apr.dev"

[provider]
cluster = "localnet"
wallet = "~/.config/solana/id.json"
"#
    )
}

const DESERIALIZE_PROOF_FN: &str = r#"
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof, ()> {
    const G1: usize = 64;
    const FR: usize = 32;

    let mut off = 0;

    fn read_g1(bytes: &[u8], off: &mut usize) -> Result<genshi_math::G1Affine, ()> {
        if bytes.len() < *off + G1 { return Err(()); }
        let mut buf = [0u8; G1];
        buf.copy_from_slice(&bytes[*off..*off + G1]);
        *off += G1;
        genshi_math::G1Affine::from_uncompressed_bytes(&buf).ok_or(())
    }

    fn read_fr(bytes: &[u8], off: &mut usize) -> Result<Fr, ()> {
        if bytes.len() < *off + FR { return Err(()); }
        let mut buf = [0u8; FR];
        buf.copy_from_slice(&bytes[*off..*off + FR]);
        *off += FR;
        Fr::from_be_bytes_canonical(&buf).ok_or(())
    }

    let w_comms = [
        read_g1(bytes, &mut off)?,
        read_g1(bytes, &mut off)?,
        read_g1(bytes, &mut off)?,
        read_g1(bytes, &mut off)?,
    ];
    let z_comm = read_g1(bytes, &mut off)?;

    if bytes.len() < off + 4 { return Err(()); }
    let n_t = u32::from_le_bytes(bytes[off..off+4].try_into().map_err(|_| ())?) as usize;
    off += 4;
    let mut t_comms = Vec::with_capacity(n_t);
    for _ in 0..n_t {
        t_comms.push(read_g1(bytes, &mut off)?);
    }

    let w_evals = [read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?];
    let sigma_evals = [read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?];
    let z_eval = read_fr(bytes, &mut off)?;
    let z_omega_eval = read_fr(bytes, &mut off)?;
    let selector_evals = [
        read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?,
        read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?, read_fr(bytes, &mut off)?,
        read_fr(bytes, &mut off)?,
    ];
    let t_eval = read_fr(bytes, &mut off)?;
    let w_zeta = read_g1(bytes, &mut off)?;
    let w_zeta_omega = read_g1(bytes, &mut off)?;

    Ok(Proof {
        w_comms, z_comm, t_comms, w_evals, sigma_evals,
        z_eval, z_omega_eval, selector_evals, t_eval,
        w_zeta, w_zeta_omega,
    })
}

pub fn deserialize_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, ()> {
    const FR: usize = 32;
    if bytes.len() % FR != 0 { return Err(()); }
    let n = bytes.len() / FR;
    let mut pis = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * FR;
        let mut buf = [0u8; FR];
        buf.copy_from_slice(&bytes[start..start + FR]);
        pis.push(Fr::from_be_bytes_canonical(&buf).ok_or(())?);
    }
    Ok(pis)
}
"#;

#[derive(Debug)]
pub enum EmitError {
    NoCircuits,
    InvalidVk(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for EmitError {
    fn from(e: std::io::Error) -> Self {
        EmitError::Io(e)
    }
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmitError::NoCircuits => write!(f, "No circuits configured"),
            EmitError::InvalidVk(name) => write!(f, "Invalid VK bytes for circuit '{name}'"),
            EmitError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for EmitError {}
