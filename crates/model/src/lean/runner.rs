//! Lean invocation and acceptance.
//!
//! A theorem is kernel-checked only if ALL hold:
//! 1. the source contains no forbidden construct (sorry, axiom, native_decide, ...);
//! 2. `lean` exits 0 with no `error:` diagnostics;
//! 3. `#print axioms` was printed for every audited theorem;
//! 4. every reported axiom is in the foundation set (a failed proof reports `sorryAx`).
//!
//! Only then is a [`KernelAcceptance`] constructed.

use super::emit::forbidden_constructs;
use proof_it_core::process::{RunOptions, run, scrubbed_env, which};
use proof_it_core::property::LEAN_TOOLCHAIN;
use proof_it_core::types::KernelAcceptance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

/// Lean's standard foundations. Anything else is reported as an extra axiom.
pub const FOUNDATION_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toolchain {
    pub lean: PathBuf,
    pub version: String,
    /// Directory containing `lean-toolchain`, used as cwd so elan selects the pinned toolchain.
    pub dir: PathBuf,
}

/// Locate Lean and pin the toolchain (from the embedded `lean/lean-toolchain`).
pub fn toolchain() -> Option<&'static Toolchain> {
    static TC: OnceLock<Option<Toolchain>> = OnceLock::new();
    TC.get_or_init(|| {
        let lean = which("lean")?;
        let dir = std::env::temp_dir().join(format!("proof-it-lean-{}", proof_it_core::store::sha256_hex(LEAN_TOOLCHAIN.as_bytes()).get(..12).unwrap_or("x")));
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(dir.join("lean-toolchain"), LEAN_TOOLCHAIN).ok()?;
        let r = run(
            &[lean.display().to_string(), "--version".into()],
            &RunOptions { env: Some(scrubbed_env(&[])), ..RunOptions::new(&dir, Duration::from_secs(300)) },
        );
        if !r.success() {
            return None;
        }
        let version = r.stdout.lines().next().unwrap_or("unknown").trim().to_owned();
        Some(Toolchain { lean, version, dir })
    })
    .as_ref()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub line: u32,
    pub column: u32,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeanCheck {
    pub accepted: bool,
    pub axioms: BTreeMap<String, Option<Vec<String>>>,
    pub extra_axioms: Vec<String>,
    pub forbidden: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub reason: String,
    #[serde(skip)]
    pub raw_output: String,
    pub toolchain: Option<String>,
}

impl LeanCheck {
    /// Turn an accepted check into the capability required to mark PROVEN.
    pub fn acceptance(&self, proof_file: &str) -> Option<KernelAcceptance> {
        if !self.accepted {
            return None;
        }
        let axioms: Vec<String> = self.axioms.values().flatten().flatten().cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        Some(KernelAcceptance::from_lean_check(
            self.axioms.keys().cloned().collect(),
            axioms,
            self.toolchain.clone().unwrap_or_default(),
            proof_file.to_owned(),
        ))
    }
}

pub fn parse_output(out: &str, theorems: &[String]) -> (Vec<Diagnostic>, BTreeMap<String, Option<Vec<String>>>) {
    let mut diags = Vec::new();
    let mut current: Option<Diagnostic> = None;
    let mut axioms: BTreeMap<String, Option<Vec<String>>> = theorems.iter().map(|t| (t.clone(), None)).collect();
    // Lean wraps long `#print axioms` lines: join continuation lines of an open `[...` list.
    let mut joined: Vec<String> = Vec::new();
    for line in out.lines() {
        match joined.last_mut() {
            Some(prev) if prev.contains("depends on axioms: [") && !prev.ends_with(']') => {
                prev.push(' ');
                prev.push_str(line.trim());
            }
            _ => joined.push(line.to_owned()),
        }
    }
    for line in joined.iter().map(String::as_str) {
        // `<file>:<line>:<col>: error: msg`
        let header = line
            .find(": error: ")
            .map(|i| (i, "error"))
            .or_else(|| line.find(": warning: ").map(|i| (i, "warning")))
            .or_else(|| line.find(": info: ").map(|i| (i, "info")));
        if let Some((i, sev)) = header {
            let loc: Vec<&str> = line[..i].rsplitn(3, ':').collect();
            if loc.len() == 3
                && let (Ok(c), Ok(l)) = (loc[0].parse::<u32>(), loc[1].parse::<u32>())
            {
                if let Some(d) = current.take() {
                    diags.push(d);
                }
                let msg = line[i + sev.len() + 4..].to_owned();
                current = Some(Diagnostic { line: l, column: c, severity: sev.to_owned(), message: msg });
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix('\'')
            && let Some((name, tail)) = rest.split_once('\'')
            && let Some(slot) = axioms.get_mut(name)
        {
            if let Some(list) = tail.strip_prefix(" depends on axioms: [").and_then(|t| t.strip_suffix(']')) {
                *slot = Some(list.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect());
            } else if tail.trim() == "does not depend on any axioms" {
                *slot = Some(vec![]);
            }
            if let Some(d) = current.take() {
                diags.push(d);
            }
            continue;
        }
        if let Some(d) = current.as_mut() {
            d.message.push('\n');
            d.message.push_str(line);
        }
    }
    if let Some(d) = current {
        diags.push(d);
    }
    (diags, axioms)
}

/// Check a Lean file. Never panics; every failure becomes a non-accepted check with a reason.
pub fn check_file(path: &Path, theorems: &[String], timeout: Duration) -> LeanCheck {
    let source = std::fs::read_to_string(path).unwrap_or_default();
    let forbidden: Vec<String> = forbidden_constructs(&source).into_iter().map(str::to_owned).collect();
    let mut c = LeanCheck {
        accepted: false,
        axioms: BTreeMap::new(),
        extra_axioms: vec![],
        forbidden: forbidden.clone(),
        diagnostics: vec![],
        timed_out: false,
        duration_ms: 0,
        reason: String::new(),
        raw_output: String::new(),
        toolchain: None,
    };
    if !forbidden.is_empty() {
        c.reason = format!("source contains forbidden construct(s): {}", forbidden.join(", "));
        return c;
    }
    let Some(tc) = toolchain() else {
        c.reason = "Lean toolchain not found (install elan; see docs/formal-verification.md)".into();
        return c;
    };
    c.toolchain = Some(tc.version.clone());
    let r =
        run(&[tc.lean.display().to_string(), path.display().to_string()], &RunOptions { env: Some(scrubbed_env(&[])), ..RunOptions::new(&tc.dir, timeout) });
    c.raw_output = format!("{}{}", r.stdout, r.stderr).trim().to_owned();
    c.duration_ms = u64::try_from(r.duration.as_millis()).unwrap_or(u64::MAX);
    if r.timed_out {
        c.timed_out = true;
        c.reason = format!("Lean timed out after {}s", timeout.as_secs());
        return c;
    }
    if let Some(e) = &r.spawn_error {
        c.reason = format!("could not run Lean: {e}");
        return c;
    }
    let (diags, axioms) = parse_output(&c.raw_output, theorems);
    let errors: Vec<&Diagnostic> = diags.iter().filter(|d| d.severity == "error").collect();
    let missing: Vec<&String> = axioms.iter().filter(|(_, v)| v.is_none()).map(|(k, _)| k).collect();
    let mut extra: Vec<String> = axioms.values().flatten().flatten().filter(|a| !FOUNDATION_AXIOMS.contains(&a.as_str())).cloned().collect();
    extra.sort();
    extra.dedup();
    c.reason = if r.exit_code != Some(0) || !errors.is_empty() {
        format!(
            "Lean rejected the proof: {}",
            errors.first().map_or_else(|| format!("exit code {:?}", r.exit_code), |d| d.message.lines().next().unwrap_or("").to_owned())
        )
    } else if !missing.is_empty() {
        format!("axiom report missing for {}", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
    } else if !extra.is_empty() {
        format!("proof depends on non-foundational axiom(s): {}", extra.join(", "))
    } else {
        "accepted by the Lean kernel".into()
    };
    c.accepted = r.exit_code == Some(0) && errors.is_empty() && missing.is_empty() && extra.is_empty();
    c.diagnostics = diags;
    c.axioms = axioms;
    c.extra_axioms = extra;
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_axioms_and_errors() {
        let out = "f.lean:3:2: error: unsolved goals\ncase true\n⊢ False\n'NS.t' depends on axioms: [propext, sorryAx]\n'NS.u' does not depend on any axioms\n";
        let (d, a) = parse_output(out, &["NS.t".into(), "NS.u".into(), "NS.v".into()]);
        assert_eq!(d.len(), 1);
        assert!(d[0].message.contains("unsolved goals"));
        assert_eq!(a["NS.t"], Some(vec!["propext".to_owned(), "sorryAx".to_owned()]));
        assert_eq!(a["NS.u"], Some(vec![]));
        assert_eq!(a["NS.v"], None);
    }

    #[test]
    fn parses_wrapped_axiom_lists() {
        let out = "'NS.a_very_long_theorem_name' depends on axioms: [propext,\n Quot.sound]\n";
        let (_, a) = parse_output(out, &["NS.a_very_long_theorem_name".into()]);
        assert_eq!(a["NS.a_very_long_theorem_name"], Some(vec!["propext".to_owned(), "Quot.sound".to_owned()]));
    }
}
