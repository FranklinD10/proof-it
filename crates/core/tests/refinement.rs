//! Refinement check: the Rust decision functions equal the Lean model
//! (`lean/ProofIt/Models/Assurance.lean`, whose safety theorems are proven)
//! on every input. Lean evaluates the model; we compare line by line.

use proof_it_core::decision::{Decision, Outcome, classify, decide};
use std::path::Path;
use std::process::Command;

#[test]
fn rust_implementation_refines_lean_model() {
    let lean_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../lean");
    let home = std::env::var("HOME").unwrap_or_default();
    let lake = [format!("{home}/.elan/bin/lake"), "lake".to_owned()].into_iter().find(|p| Command::new(p).arg("--version").output().is_ok());
    let Some(lake) = lake else {
        eprintln!("SKIPPED: lake not installed");
        return;
    };
    let build = Command::new(&lake).arg("build").current_dir(&lean_dir).output().expect("lake build");
    assert!(build.status.success(), "lake build failed: {}", String::from_utf8_lossy(&build.stdout));
    let out = Command::new(&lake).args(["env", "lean", "ProofIt/SelfCheck/Tables.lean"]).current_dir(&lean_dir).output().expect("lean");
    let text = String::from_utf8_lossy(&out.stdout);
    let b = |s: &str| s == "true";
    let mut checked = 0;
    for line in text.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts.as_slice() {
            ["classify", k, v, f, r, a, expected] => {
                let got = classify(b(k), b(v), b(f), b(r), b(a));
                assert_eq!(got.label(), *expected, "classify({k},{v},{f},{r},{a})");
                checked += 1;
            }
            ["decide", os, blk, hum, expected] => {
                let outcomes: Vec<Outcome> = os
                    .split(',')
                    .filter(|x| !x.is_empty())
                    .map(|x| match x {
                        "met" => Outcome::Met,
                        "human" => Outcome::NeedsHuman,
                        _ => Outcome::Blocks,
                    })
                    .collect();
                let got = match decide(&outcomes, b(blk), b(hum)) {
                    Decision::AutoMerge => "AUTO",
                    Decision::HumanReview => "HUMAN",
                    Decision::Blocked => "BLOCKED",
                };
                assert_eq!(got, *expected, "decide({os},{blk},{hum})");
                checked += 1;
            }
            _ => {}
        }
    }
    // 32 classify rows + 9 outcome lists × 4 flag combinations.
    assert_eq!(checked, 32 + 36, "unexpected table size; Lean output:\n{text}");
}
