use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let core_proving = Path::new(&manifest_dir).join("../genshi-core/src/proving");
    let assets_dir = Path::new(&manifest_dir).join("assets");

    fs::create_dir_all(&assets_dir).unwrap();

    for name in &["verifier.rs", "transcript.rs", "types.rs"] {
        let src = core_proving.join(name);
        let dst = assets_dir.join(name);
        fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!("Failed to copy {}: {e}", src.display());
        });
        println!("cargo:rerun-if-changed={}", src.display());
    }
}
