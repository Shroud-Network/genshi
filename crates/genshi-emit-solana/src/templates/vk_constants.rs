use genshi_core::proving::types::VerificationKey;
use genshi_math::{Fr, G1Affine};
use std::fmt::Write;

pub fn generate(circuits: &[(String, VerificationKey)]) -> String {
    let mut out = String::new();
    writeln!(out, "use genshi_math::{{Fr, G1Affine}};").unwrap();
    writeln!(out, "use crate::types::VerificationKey;").unwrap();
    writeln!(out).unwrap();

    for (name, vk) in circuits {
        write_vk_loader(&mut out, name, vk);
    }
    out
}

fn write_vk_loader(out: &mut String, name: &str, vk: &VerificationKey) {
    let fn_name = format!("load_{name}_vk");

    writeln!(out, "#[inline(never)]").unwrap();
    writeln!(out, "pub fn {fn_name}() -> VerificationKey {{").unwrap();
    writeln!(out, "    VerificationKey {{").unwrap();
    write_g1_field(out, "q_m_comm", &vk.q_m_comm);
    write_g1_field(out, "q_1_comm", &vk.q_1_comm);
    write_g1_field(out, "q_2_comm", &vk.q_2_comm);
    write_g1_field(out, "q_3_comm", &vk.q_3_comm);
    write_g1_field(out, "q_4_comm", &vk.q_4_comm);
    write_g1_field(out, "q_c_comm", &vk.q_c_comm);
    write_g1_field(out, "q_arith_comm", &vk.q_arith_comm);

    writeln!(out, "        sigma_comms: [").unwrap();
    for s in &vk.sigma_comms {
        writeln!(out, "            {},", g1_literal(s)).unwrap();
    }
    writeln!(out, "        ],").unwrap();

    writeln!(out, "        domain_size: {},", vk.domain_size).unwrap();
    writeln!(out, "        num_public_inputs: {},", vk.num_public_inputs).unwrap();
    writeln!(out, "        omega: {},", fr_literal(&vk.omega)).unwrap();

    writeln!(out, "        k: [").unwrap();
    for k in &vk.k {
        writeln!(out, "            {},", fr_literal(k)).unwrap();
    }
    writeln!(out, "        ],").unwrap();

    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn write_g1_field(out: &mut String, name: &str, point: &G1Affine) {
    writeln!(out, "        {name}: {},", g1_literal(point)).unwrap();
}

fn g1_literal(point: &G1Affine) -> String {
    let bytes = point.to_uncompressed_bytes();
    format!("G1Affine::from_raw({})", byte_array_literal(&bytes))
}

fn fr_literal(scalar: &Fr) -> String {
    let bytes = scalar.to_be_bytes();
    format!("Fr::from_be_bytes_mod_order(&{})", byte_array_literal(&bytes))
}

fn byte_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        if i % 16 == 0 && i > 0 {
            out.push_str("\n            ");
        }
        write!(out, "0x{b:02x}").unwrap();
    }
    out.push(']');
    out
}
