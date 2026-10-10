//! Embed the property library, Semgrep rules and the Lean toolchain pin so the
//! `proof-it` binary is self-contained.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn collect(dir: &Path, ext: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            collect(&p, ext, out);
        } else if p.extension().and_then(|x| x.to_str()).is_some_and(|x| ext.contains(&x)) {
            out.push(p);
        }
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let repo = manifest.join("../..").canonicalize().expect("repository root");
    let mut code = String::new();
    for (name, sub, exts) in [("PROPERTY_LIBRARY", "properties", &["yaml", "yml"][..]), ("SEMGREP_RULES", "rules", &["yaml", "yml"][..])] {
        let mut files = Vec::new();
        collect(&repo.join(sub), exts, &mut files);
        writeln!(code, "pub static {name}: &[(&str, &str)] = &[").ok();
        for f in &files {
            let rel = f.strip_prefix(&repo).expect("under repo").display().to_string();
            writeln!(code, "    ({rel:?}, include_str!({:?})),", f.display().to_string()).ok();
        }
        writeln!(code, "];").ok();
        println!("cargo:rerun-if-changed={}", repo.join(sub).display());
    }
    let cov = repo.join("coverage/coverage.yaml");
    writeln!(code, "pub static COVERAGE: &str = include_str!({:?});", cov.display().to_string()).ok();
    println!("cargo:rerun-if-changed={}", cov.display());
    let tc = repo.join("lean/lean-toolchain");
    writeln!(code, "pub static LEAN_TOOLCHAIN: &str = include_str!({:?});", tc.display().to_string()).ok();
    println!("cargo:rerun-if-changed={}", tc.display());
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("embedded.rs");
    std::fs::write(out, code).expect("write embedded.rs");
}
