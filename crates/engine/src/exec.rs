//! Sandboxed execution of code from the analysed repository.
//!
//! The most dangerous thing Proof-It does, so it is opt-in and layered:
//!  1. only when explicitly allowed (config or `--allow-exec`), never in `--safe`;
//!  2. sources are transpiled by oxc (type stripping only) into a private
//!     directory — no tsc, no build scripts, no package installs;
//!  3. Node's permission model: read access only to that directory and the
//!     repository's node_modules; no writes, child processes, workers, addons;
//!  4. bubblewrap when available: read-only root, private /tmp, no network,
//!     own PID namespace;
//!  5. heap limit and wall-clock timeout.

use proof_it_core::paths::safe_join;
use proof_it_core::process::{RunOptions, Sandbox, run, sandbox_available, scrubbed_env, which};
use proof_it_core::project::SourceFile;
use proof_it_core::{Error, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

const HARNESS: &str = include_str!("harness.mjs");
#[allow(clippy::expect_used)]
static IMPORT_SPEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"((?:from|import)\s*\(?\s*)"(\.{1,2}/[^"]+)""#).expect("static regex"));

#[derive(Debug, Clone)]
pub struct Outcome {
    pub threw: bool,
    pub error: Option<String>,
    pub returned: Option<serde_json::Value>,
    pub args: Vec<serde_json::Value>,
}

#[derive(Debug)]
pub struct Batch {
    pub ok: bool,
    pub error: Option<String>,
    pub outcomes: Vec<Outcome>,
    pub sandboxed: bool,
}

pub struct Executor {
    root: PathBuf,
    dir: tempfile::TempDir,
    node: PathBuf,
    pub sandboxed: bool,
    pub transpile_errors: Vec<(String, String)>,
}

fn mjs_path(p: &str) -> String {
    let stem = p.rsplit_once('.').map_or(p, |(s, _)| s);
    format!("{stem}.mjs")
}

fn rel_spec(from: &str, to: &str) -> String {
    let from_dir: Vec<&str> = from.split('/').collect::<Vec<_>>().split_last().map(|(_, d)| d.to_vec()).unwrap_or_default();
    let to_parts: Vec<&str> = to.split('/').collect();
    let common = from_dir.iter().zip(&to_parts).take_while(|(a, b)| a == b).count();
    let ups = from_dir.len() - common;
    let mut s = if ups == 0 { "./".to_owned() } else { "../".repeat(ups) };
    s.push_str(&to_parts[common..].join("/"));
    s
}

impl Executor {
    pub fn new(root: &Path, files: &[SourceFile], allowed: bool, safe_mode: bool) -> Result<Self> {
        if safe_mode {
            return Err(Error::Usage("executing repository code is disabled in --safe mode".into()));
        }
        if !allowed {
            return Err(Error::Usage("executing repository code is not allowed; pass --allow-exec or set testing.allow_execution: true".into()));
        }
        let node = which("node").ok_or_else(|| Error::Environment("node is required to execute JavaScript/TypeScript targets".into()))?;
        let dir = tempfile::Builder::new().prefix("proofit-exec-").tempdir().map_err(|e| Error::io(std::env::temp_dir(), e))?;
        let known: HashSet<String> = files.iter().map(|f| f.path.clone()).collect();
        let mut errors = Vec::new();
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f.abs) else {
                continue;
            };
            let js = match proof_it_lang_ts::transpile::to_esm(&f.path, &text) {
                Ok(js) => js,
                Err(e) => {
                    errors.push((f.path.clone(), e));
                    continue;
                }
            };
            // Rewrite relative imports to the transpiled .mjs files.
            let rewritten = IMPORT_SPEC.replace_all(&js, |c: &regex::Captures<'_>| {
                let spec = &c[2];
                match proof_it_lang_ts::module::resolve_import(&f.path, spec, &known) {
                    Some(target) => {
                        format!("{}\"{}\"", &c[1], rel_spec(&f.path, &mjs_path(&target)))
                    }
                    None => c[0].to_owned(),
                }
            });
            let out = safe_join(dir.path(), &mjs_path(&f.path))?;
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
            std::fs::write(&out, rewritten.as_bytes()).map_err(|e| Error::io(&out, e))?;
        }
        std::fs::write(dir.path().join("package.json"), r#"{"type":"module"}"#).map_err(|e| Error::io(dir.path(), e))?;
        std::fs::write(dir.path().join(".proofit-harness.mjs"), HARNESS).map_err(|e| Error::io(dir.path(), e))?;
        let nm = root.join("node_modules");
        if nm.is_dir() {
            let _ = std::os::unix::fs::symlink(&nm, dir.path().join("node_modules"));
        }
        Ok(Self { root: root.to_path_buf(), dir, node, sandboxed: sandbox_available(), transpile_errors: errors })
    }

    pub fn call(&self, module: &str, export: &str, cases: &[Vec<serde_json::Value>], timeout: Duration) -> Batch {
        let Ok(module_abs) = safe_join(self.dir.path(), &mjs_path(module)) else {
            return Batch { ok: false, error: Some(format!("invalid module path {module}")), outcomes: vec![], sandboxed: false };
        };
        let nm = self.root.join("node_modules");
        let mut readable = vec![self.dir.path().to_path_buf()];
        if nm.is_dir() {
            readable.push(nm);
        }
        let mut argv = vec![self.node.display().to_string(), "--max-old-space-size=512".into(), "--permission".into()];
        argv.extend(readable.iter().map(|r| format!("--allow-fs-read={}", r.display())));
        argv.push(self.dir.path().join(".proofit-harness.mjs").display().to_string());
        let spec = serde_json::json!({ "module": module_abs, "exportName": export, "cases": cases.iter().map(|c| serde_json::json!({ "args": c })).collect::<Vec<_>>(), "caseTimeoutMs": 2000 });
        let dirs = self.dir.path().display().to_string();
        let mut o = RunOptions::new(self.dir.path(), timeout);
        o.env = Some(scrubbed_env(&[("NODE_ENV", "test"), ("HOME", &dirs)]));
        o.stdin = Some(spec.to_string().into_bytes());
        o.max_output_bytes = 32 * 1024 * 1024;
        if self.sandboxed {
            o.sandbox = Some(Sandbox { writable: vec![], readable, network: false });
        }
        let r = run(&argv, &o);
        if r.timed_out {
            return Batch { ok: false, error: Some(format!("execution timed out after {}s", timeout.as_secs())), outcomes: vec![], sandboxed: r.sandboxed };
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Out {
            load_error: Option<String>,
            #[serde(default)]
            outcomes: Vec<RawOutcome>,
        }
        #[derive(Deserialize)]
        struct RawOutcome {
            threw: bool,
            error: Option<String>,
            returned: Option<serde_json::Value>,
            #[serde(default)]
            args: Vec<serde_json::Value>,
        }
        let parsed: Out = match serde_json::from_str(&r.stdout) {
            Ok(p) => p,
            Err(_) => {
                let tail: Vec<&str> = r.stderr.lines().rev().take(3).collect();
                return Batch {
                    ok: false,
                    error: Some(format!(
                        "harness produced no result (exit {:?}): {}",
                        r.exit_code,
                        r.spawn_error.clone().unwrap_or_else(|| tail.into_iter().rev().collect::<Vec<_>>().join(" "))
                    )),
                    outcomes: vec![],
                    sandboxed: r.sandboxed,
                };
            }
        };
        if let Some(e) = parsed.load_error {
            return Batch { ok: false, error: Some(format!("could not load {module}: {e}")), outcomes: vec![], sandboxed: r.sandboxed };
        }
        Batch {
            ok: true,
            error: None,
            outcomes: parsed.outcomes.into_iter().map(|o| Outcome { threw: o.threw, error: o.error, returned: o.returned, args: o.args }).collect(),
            sandboxed: r.sandboxed,
        }
    }
}

/// Decode the harness number encoding (`{"$num": "NaN"}`) into an f64.
pub fn as_number(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::Object(o) => o.get("$num").and_then(|x| x.as_str()).and_then(|s| match s {
            "NaN" => Some(f64::NAN),
            "Infinity" => Some(f64::INFINITY),
            "-Infinity" => Some(f64::NEG_INFINITY),
            _ => s.parse().ok(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_specifiers() {
        assert_eq!(rel_spec("src/a/b.ts", "src/c.mjs"), "../c.mjs");
        assert_eq!(rel_spec("src/a.ts", "src/b.mjs"), "./b.mjs");
        assert_eq!(mjs_path("src/x.ts"), "src/x.mjs");
    }
}
