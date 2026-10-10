//! Adapters for external analyzers (Semgrep, gitleaks, osv-scanner).
//!
//! Each adapter is optional: a missing tool yields stage status
//! `not-installed`, never "passed". Tools run with a timeout, a scrubbed
//! environment, a private HOME, and inside bubblewrap when available
//! (read-only filesystem; network only for osv-scanner). None of them executes
//! code from the analysed repository. Raw output is stored as evidence.

use proof_it_core::process::{RunOptions, RunResult, Sandbox, run, sandbox_available, scrubbed_env, which};
use proof_it_core::property::SEMGREP_RULES;
use proof_it_core::redact::redact_secret;
use proof_it_core::store::{Artifact, RunStore};
use proof_it_core::types::*;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

pub struct ExternalOutput {
    pub findings: Vec<Finding>,
    pub stage: StageRun,
}

fn stage(name: &str, r: &RunResult, ok: bool, version: Option<String>, detail: String) -> StageRun {
    let status = if r.timed_out {
        StageStatus::TimedOut
    } else if ok {
        StageStatus::Ran
    } else {
        StageStatus::Failed
    };
    StageRun {
        name: name.into(),
        status,
        duration_ms: u64::try_from(r.duration.as_millis()).unwrap_or(0),
        detail: Some(format!("{detail}{}", if r.sandboxed { " (sandboxed)" } else { "" })),
        version,
    }
}

fn missing(name: &str) -> ExternalOutput {
    ExternalOutput { findings: vec![], stage: StageRun::new(name, StageStatus::NotInstalled, 0, "not installed — this check did NOT run") }
}

fn version(bin: &Path, args: &[&str]) -> Option<String> {
    let mut argv = vec![bin.display().to_string()];
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let r = run(&argv, &RunOptions::new(std::env::temp_dir(), Duration::from_secs(60)));
    r.success().then(|| format!("{}{}", r.stdout, r.stderr).lines().next().unwrap_or("").trim().to_owned()).filter(|v| !v.is_empty())
}

fn tool_run(argv: Vec<String>, root: &Path, tmp: &Path, network: bool, timeout: Duration) -> RunResult {
    let t = tmp.display().to_string();
    let mut o = RunOptions::new(root, timeout);
    o.max_output_bytes = 64 * 1024 * 1024;
    o.env = Some(scrubbed_env(&[
        ("HOME", &t),
        ("XDG_CONFIG_HOME", &t),
        ("XDG_CACHE_HOME", &t),
        ("SEMGREP_SEND_METRICS", "off"),
        ("SEMGREP_ENABLE_VERSION_CHECK", "0"),
    ]));
    if sandbox_available() {
        o.sandbox = Some(Sandbox { writable: vec![tmp.to_path_buf()], readable: vec![root.to_path_buf()], network });
    }
    run(&argv, &o)
}

fn rel(root: &Path, p: &str) -> String {
    Path::new(p).strip_prefix(root).map_or_else(|_| p.to_owned(), |x| x.display().to_string())
}

#[derive(Deserialize)]
struct SgOut {
    #[serde(default)]
    results: Vec<SgResult>,
}
#[derive(Deserialize)]
struct SgResult {
    check_id: String,
    path: String,
    start: SgPos,
    extra: SgExtra,
}
#[derive(Deserialize)]
struct SgPos {
    line: u32,
    col: u32,
}
#[derive(Deserialize)]
struct SgExtra {
    message: String,
    severity: String,
    #[serde(default)]
    lines: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

pub fn semgrep(root: &Path, store: &RunStore, timeout: Duration) -> ExternalOutput {
    let Some(bin) = which("semgrep") else {
        return missing("semgrep");
    };
    let Ok(tmp) = tempfile::Builder::new().prefix("proofit-semgrep-").tempdir() else {
        return missing("semgrep");
    };
    let rules_dir = tmp.path().join("rules");
    if std::fs::create_dir(&rules_dir).is_err() {
        return missing("semgrep");
    }
    for (name, text) in SEMGREP_RULES {
        let _ = std::fs::write(rules_dir.join(Path::new(name).file_name().unwrap_or_default()), text);
    }
    let ver = version(&bin, &["--version"]);
    // Only Proof-It's bundled rules: `--config auto` would contact the registry.
    let argv = [
        bin.display().to_string(),
        "scan".into(),
        "--config".into(),
        rules_dir.display().to_string(),
        "--json".into(),
        "--metrics=off".into(),
        "--disable-version-check".into(),
        "--quiet".into(),
        "--no-git-ignore".into(),
        "--timeout".into(),
        "30".into(),
        "--exclude".into(),
        "node_modules".into(),
        "--exclude".into(),
        ".proof-it".into(),
        root.display().to_string(),
    ]
    .to_vec();
    let r = tool_run(argv, root, tmp.path(), false, timeout);
    let _ = store.write_artifact(Artifact::Tools, "semgrep.json", if r.stdout.is_empty() { &r.stderr } else { &r.stdout });
    if !matches!(r.exit_code, Some(0 | 1)) {
        return ExternalOutput {
            findings: vec![],
            stage: stage("semgrep", &r, false, ver, r.spawn_error.clone().unwrap_or_else(|| r.stderr.lines().last().unwrap_or("").to_owned())),
        };
    }
    let out: SgOut = serde_json::from_str(&r.stdout).unwrap_or(SgOut { results: vec![] });
    let findings: Vec<Finding> = out
        .results
        .into_iter()
        .map(|x| {
            let location = SourceLocation {
                file: rel(root, &x.path),
                line: x.start.line,
                column: Some(x.start.col),
                end_line: None,
                snippet: Some(x.extra.lines.trim().chars().take(160).collect()),
            };
            let rule_id = format!("semgrep:{}", x.check_id.rsplit('.').next().unwrap_or(&x.check_id));
            let severity = match x.extra.severity.as_str() {
                "ERROR" => Severity::High,
                "WARNING" => Severity::Medium,
                _ => Severity::Low,
            };
            let cwe = match &x.extra.metadata["cwe"] {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
                _ => vec![],
            };
            Finding {
                id: fingerprint(&rule_id, Some(&location), ""),
                property_id: x.extra.metadata["proof_it_property"].as_str().map(str::to_owned),
                title: x.extra.message.split('.').next().unwrap_or(&rule_id).chars().take(80).collect(),
                rule_id,
                source: FindingSource::External,
                severity,
                confidence: Confidence::Medium,
                location: Some(location),
                description: x.extra.message,
                evidence: vec![
                    Evidence::new(EvidenceKind::ExternalTool, format!("semgrep {} rule {}", ver.clone().unwrap_or_default(), x.check_id))
                        .with_artifact("tools/semgrep.json"),
                ],
                recommendation: None,
                cwe,
                suppressed: None,
                baseline: None,
            }
        })
        .collect();
    let n = findings.len();
    ExternalOutput { findings, stage: stage("semgrep", &r, true, ver, format!("{n} result(s) from bundled rules")) }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Leak {
    #[serde(rename = "RuleID")]
    rule_id: String,
    description: String,
    file: String,
    start_line: u32,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    r#match: String,
}

pub fn gitleaks(root: &Path, store: &RunStore, timeout: Duration) -> ExternalOutput {
    let Some(bin) = which("gitleaks") else {
        return missing("gitleaks");
    };
    let Ok(tmp) = tempfile::Builder::new().prefix("proofit-gitleaks-").tempdir() else {
        return missing("gitleaks");
    };
    let ver = version(&bin, &["version"]);
    let report = tmp.path().join("report.json");
    // `dir` scans the working tree only: no git invocation inside the repository.
    let argv = [
        bin.display().to_string(),
        "dir".into(),
        root.display().to_string(),
        "--no-banner".into(),
        "--redact=100".into(),
        "--report-format".into(),
        "json".into(),
        "--report-path".into(),
        report.display().to_string(),
        "--exit-code".into(),
        "0".into(),
        "--max-target-megabytes".into(),
        "2".into(),
        "--log-level".into(),
        "error".into(),
    ]
    .to_vec();
    let r = tool_run(argv, root, tmp.path(), false, timeout);
    if !r.success() {
        return ExternalOutput {
            findings: vec![],
            stage: stage("gitleaks", &r, false, ver, r.spawn_error.clone().unwrap_or_else(|| r.stderr.lines().last().unwrap_or("").to_owned())),
        };
    }
    let leaks: Vec<Leak> = std::fs::read_to_string(&report).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let findings: Vec<Finding> = leaks
        .iter()
        .map(|x| {
            // gitleaks already redacts with --redact; redact again defensively.
            let snippet =
                if x.secret.is_empty() || x.secret == "REDACTED" { x.r#match.clone() } else { x.r#match.replace(&x.secret, &redact_secret(&x.secret)) };
            let location = SourceLocation {
                file: rel(root, &x.file),
                line: x.start_line,
                column: None,
                end_line: None,
                snippet: Some(snippet.chars().take(160).collect()),
            };
            let rule_id = format!("gitleaks:{}", x.rule_id);
            Finding {
                id: fingerprint(&rule_id, Some(&location), ""),
                rule_id,
                property_id: Some("DATA-002".into()),
                title: x.description.clone(),
                source: FindingSource::External,
                severity: Severity::High,
                confidence: Confidence::Medium,
                location: Some(location),
                description: format!("{} (value redacted)", x.description),
                evidence: vec![Evidence::new(EvidenceKind::ExternalTool, format!("gitleaks rule {}", x.rule_id)).with_artifact("tools/gitleaks.json")],
                recommendation: Some("Rotate the credential and remove it from history.".into()),
                cwe: vec!["CWE-798".into()],
                suppressed: None,
                baseline: None,
            }
        })
        .collect();
    let stored: Vec<serde_json::Value> = leaks.iter().map(|x| serde_json::json!({ "RuleID": x.rule_id, "Description": x.description, "File": rel(root, &x.file), "StartLine": x.start_line, "Secret": "REDACTED" })).collect();
    let _ = store.write_artifact(Artifact::Tools, "gitleaks.json", &serde_json::to_string_pretty(&stored).unwrap_or_default());
    let n = findings.len();
    ExternalOutput { findings, stage: stage("gitleaks", &r, true, ver, format!("{n} leak(s)")) }
}

pub fn osv(root: &Path, store: &RunStore, timeout: Duration, offline: bool) -> ExternalOutput {
    let Some(bin) = which("osv-scanner") else {
        return missing("osv-scanner");
    };
    if offline {
        return ExternalOutput {
            findings: vec![],
            stage: StageRun::new(
                "osv-scanner",
                StageStatus::Skipped,
                0,
                "needs network (OSV API); skipped in --offline/--quick mode — dependency vulnerabilities were NOT checked",
            ),
        };
    }
    let Ok(tmp) = tempfile::Builder::new().prefix("proofit-osv-").tempdir() else {
        return missing("osv-scanner");
    };
    let ver = version(&bin, &["--version"]);
    let argv = [
        bin.display().to_string(),
        "scan".into(),
        "source".into(),
        "-r".into(),
        "--format".into(),
        "json".into(),
        "--allow-no-lockfiles".into(),
        "--verbosity".into(),
        "error".into(),
        root.display().to_string(),
    ]
    .to_vec();
    let r = tool_run(argv, root, tmp.path(), true, timeout);
    let _ = store.write_artifact(Artifact::Tools, "osv.json", if r.stdout.is_empty() { &r.stderr } else { &r.stdout });
    // osv-scanner: 0 clean, 1 vulnerabilities found, 128 no packages.
    if r.exit_code == Some(128) {
        return ExternalOutput { findings: vec![], stage: stage("osv-scanner", &r, true, ver, "no lockfiles found".into()) };
    }
    if !matches!(r.exit_code, Some(0 | 1)) {
        return ExternalOutput {
            findings: vec![],
            stage: stage("osv-scanner", &r, false, ver, r.spawn_error.clone().unwrap_or_else(|| r.stderr.lines().last().unwrap_or("").to_owned())),
        };
    }
    let v: serde_json::Value = serde_json::from_str(&r.stdout).unwrap_or_default();
    let mut findings = Vec::new();
    for res in v["results"].as_array().into_iter().flatten() {
        let file = rel(root, res["source"]["path"].as_str().unwrap_or(""));
        for p in res["packages"].as_array().into_iter().flatten() {
            let (name, ver_s, eco) = (
                p["package"]["name"].as_str().unwrap_or("?"),
                p["package"]["version"].as_str().unwrap_or("?"),
                p["package"]["ecosystem"].as_str().unwrap_or("?"),
            );
            for g in p["groups"].as_array().into_iter().flatten() {
                let ids: Vec<String> = g["ids"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_owned)).collect();
                let id = ids.iter().find(|x| x.starts_with("GHSA")).or(ids.first()).cloned().unwrap_or_else(|| "OSV".into());
                let vuln = p["vulnerabilities"].as_array().into_iter().flatten().find(|x| x["id"].as_str().is_some_and(|i| ids.iter().any(|j| j == i)));
                let summary = vuln.and_then(|x| x["summary"].as_str()).unwrap_or(&id).to_owned();
                let score: Option<f64> = g["max_severity"].as_str().and_then(|s| s.parse().ok());
                let severity = match score {
                    Some(s) if s >= 9.0 => Severity::Critical,
                    Some(s) if s >= 7.0 => Severity::High,
                    Some(s) if s >= 4.0 => Severity::Medium,
                    Some(_) => Severity::Low,
                    None => match vuln.and_then(|x| x["database_specific"]["severity"].as_str()).unwrap_or("").to_ascii_uppercase().as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH" => Severity::High,
                        "LOW" => Severity::Low,
                        _ => Severity::Medium,
                    },
                };
                let location = SourceLocation { file: file.clone(), line: 1, column: None, end_line: None, snippet: Some(format!("{name}@{ver_s}")) };
                let rule_id = format!("osv:{id}");
                findings.push(Finding {
                    id: fingerprint(&rule_id, Some(&location), name),
                    rule_id,
                    property_id: Some("INFRA-001".into()),
                    title: format!("{name}@{ver_s}: {summary}").chars().take(120).collect(),
                    source: FindingSource::Dependencies,
                    severity,
                    confidence: Confidence::High,
                    location: Some(location),
                    description: format!("{eco} package {name}@{ver_s} is affected by {}. {summary}", ids.join(", ")),
                    evidence: vec![
                        Evidence::new(EvidenceKind::ExternalTool, format!("osv-scanner advisory {}", ids.join(", "))).with_artifact("tools/osv.json"),
                    ],
                    recommendation: Some("Upgrade to a fixed version (see the advisory) or document why it does not apply.".into()),
                    cwe: vec![],
                    suppressed: None,
                    baseline: None,
                });
            }
        }
    }
    let n = findings.len();
    ExternalOutput { findings, stage: stage("osv-scanner", &r, true, ver, format!("{n} advisory(ies)")) }
}
