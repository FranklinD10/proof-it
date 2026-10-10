//! Recall on deliberately vulnerable applications (ground truth from their
//! published vulnerability lists, benchmarks/real-world/manifest.yaml).
//! Needs network to clone; run with `cargo test -p proof-it --test real_world -- --ignored`.
//! Set PROOF_IT_REAL_WORLD_ONLINE=1 to include network-backed checks (osv-scanner).

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct Manifest {
    apps: Vec<App>,
}
#[derive(Deserialize)]
struct App {
    name: String,
    url: String,
    commit: String,
    expected: Vec<Item>,
}
#[derive(Deserialize)]
struct Item {
    id: String,
    desc: String,
    kind: Option<String>,
    #[serde(rename = "match")]
    rule: Option<String>,
    /// Alternative rule ids, any of which counts (repository-level classes).
    #[serde(default)]
    any_of: Vec<String>,
    file: Option<String>,
    #[serde(default = "yes")]
    detectable: bool,
    reason: Option<String>,
    #[serde(default)]
    network: bool,
}
fn yes() -> bool {
    true
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

#[test]
#[ignore = "clones vulnerable apps from GitHub"]
fn real_world_recall() {
    let m: Manifest = serde_saphyr::from_str(&std::fs::read_to_string(root().join("benchmarks/real-world/manifest.yaml")).expect("manifest")).expect("parse");
    let online = std::env::var("PROOF_IT_REAL_WORLD_ONLINE").is_ok();
    let work = std::env::var("PROOF_IT_REAL_WORLD_DIR").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("proof-it-real-world"));
    std::fs::create_dir_all(&work).expect("work dir");
    let (mut found, mut total, mut by_design) = (0, 0, 0);
    let mut lines = Vec::new();
    for app in &m.apps {
        let dir = work.join(&app.name);
        if !dir.exists() {
            assert!(Command::new("git").args(["clone", "-q", &app.url]).arg(&dir).status().expect("git").success(), "clone {}", app.url);
        }
        assert!(Command::new("git").arg("-C").arg(&dir).args(["checkout", "-q", &app.commit]).status().expect("git").success(), "checkout {}", app.commit);
        let mut args = vec!["assure", "--safe", "--json", "--no-cache", "--out"];
        let out_dir = work.join(format!("{}-evidence", app.name));
        let out_s = out_dir.display().to_string();
        args.push(&out_s);
        if !online {
            args.push("--offline");
        }
        let o = Command::new(env!("CARGO_BIN_EXE_proof-it")).args(&args).arg(&dir).output().expect("run");
        let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{}: {e}", app.name));
        for it in &app.expected {
            if !it.detectable {
                by_design += 1;
                lines.push(format!("  n/a  {} {:<14} {} — {}", app.name, it.id, it.desc, it.reason.clone().unwrap_or_default()));
                continue;
            }
            if it.network && !online {
                lines.push(format!("  skip {} {:<14} {} (needs network)", app.name, it.id, it.desc));
                continue;
            }
            total += 1;
            // `match` and every `any_of` alternative count; `file` is a path fragment.
            let rules: Vec<String> = it.rule.iter().cloned().chain(it.any_of.iter().cloned()).collect();
            let file = it.file.clone().unwrap_or_default();
            let hit = rules.iter().any(|rule| match it.kind.as_deref() {
                Some("violated") => r["results"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x["property_id"] == rule.as_str() && x["status"] == "VIOLATED" && x["target"].as_str().is_some_and(|t| t.contains(&file))),
                _ => r["findings"].as_array().into_iter().flatten().any(|f| {
                    f["rule_id"].as_str().is_some_and(|id| id.starts_with(rule.as_str()))
                        && (file.is_empty() || f["location"]["file"].as_str().is_some_and(|p| p.contains(&file)))
                }),
            });
            if hit {
                found += 1;
            }
            lines.push(format!("  {} {} {:<14} {}", if hit { "HIT " } else { "MISS" }, app.name, it.id, it.desc));
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let recall = 100.0 * found as f64 / total.max(1) as f64;
    eprintln!(
        "\n{}\n\nRecall: {found}/{total} detectable items = {recall:.1}%  ({by_design} items not detectable by static/formal analysis, listed above)\n",
        lines.join("\n")
    );
    assert!(recall >= 85.0, "recall regressed below 85%: {recall:.1}%");
}
