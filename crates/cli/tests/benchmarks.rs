//! Benchmark-driven validation: can Proof-It catch known bugs, avoid obvious
//! false positives, and prove correct implementations? Runs the real binary.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    dir: String,
    property: Option<String>,
    target: Option<String>,
    status: Option<String>,
    finding: Option<String>,
    no_finding: Option<String>,
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn run(dir: &Path, out: &Path) -> serde_json::Value {
    let o = Command::new(env!("CARGO_BIN_EXE_proof-it"))
        .args(["assure", "--json", "--offline", "--no-external", "--no-cache", "--out"])
        .arg(out)
        .arg(dir)
        .output()
        .expect("run proof-it");
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{}: bad JSON ({e}); stderr: {}", dir.display(), String::from_utf8_lossy(&o.stderr)))
}

#[test]
fn benchmarks() {
    if Command::new("lean").arg("--version").output().is_err() && !Path::new(&format!("{}/.elan/bin/lean", std::env::var("HOME").unwrap_or_default())).exists()
    {
        eprintln!("SKIPPED: Lean not installed");
        return;
    }
    let root = repo();
    let cases: Cases =
        serde_saphyr::from_str(&std::fs::read_to_string(root.join("benchmarks/expected.yaml")).expect("expected.yaml")).expect("parse expected.yaml");
    let tmp = tempfile::tempdir().expect("tmp");
    let mut cache: std::collections::HashMap<String, serde_json::Value> = Default::default();
    let mut failures = Vec::new();
    let mut table = Vec::new();
    for c in &cases.cases {
        let report =
            cache.entry(c.dir.clone()).or_insert_with(|| run(&root.join("benchmarks").join(&c.dir), &tmp.path().join(c.dir.replace('/', "_")))).clone();
        let (what, ok, got) = if let Some(p) = &c.property {
            let hits: Vec<&serde_json::Value> = report["results"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["property_id"] == *p && c.target.as_ref().is_none_or(|t| r["target"] == *t))
                .collect();
            let got: Vec<String> = hits.iter().map(|r| format!("{} {}", r["target"].as_str().unwrap_or(""), r["status"].as_str().unwrap_or(""))).collect();
            let want = c.status.clone().unwrap_or_default();
            let ok = !hits.is_empty() && hits.iter().all(|r| r["status"] == *want);
            (format!("{p}{} = {want}", c.target.as_ref().map(|t| format!(" [{t}]")).unwrap_or_default()), ok, got.join("; "))
        } else if let Some(f) = &c.finding {
            let ok = report["findings"].as_array().into_iter().flatten().any(|x| x["rule_id"] == *f);
            (format!("finding {f}"), ok, if ok { "found".into() } else { "missing".into() })
        } else if let Some(f) = &c.no_finding {
            let ok = !report["findings"].as_array().into_iter().flatten().any(|x| x["rule_id"] == *f);
            (format!("no {f}"), ok, if ok { "absent".into() } else { "FALSE POSITIVE".into() })
        } else {
            continue;
        };
        table.push(format!("{} {:<40} {:<45} {}", if ok { "PASS" } else { "FAIL" }, c.dir, what, got));
        if !ok {
            failures.push(format!("{}: expected {what}, got {got}", c.dir));
        }
    }
    eprintln!("\n{}\n", table.join("\n"));
    assert!(failures.is_empty(), "benchmark failures:\n  {}", failures.join("\n  "));
}
