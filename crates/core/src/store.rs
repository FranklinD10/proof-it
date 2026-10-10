//! Persistent, inspectable evidence.
//!
//! ```text
//! <root>/.proof-it/runs/<run-id>/{report,summary,results,findings,metadata}.json
//!                               proofs/ counterexamples/ traces/ tools/
//! <root>/.proof-it/changes/<change-id>/{manifest.json, diff.patch, report.json, ...}
//! <root>/.proof-it/cache/proofs/<sha256>.json
//! ```
//! Every directory on the way is checked to be a real directory (a hostile
//! repository could make `.proof-it` a symlink to redirect our writes), and
//! every filename derived from analysed content is sanitised.

use crate::error::{Error, Result};
use crate::paths::{ensure_real_dir, safe_file_name, safe_join};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RUNS: &str = "runs";
pub const CHANGES: &str = "changes";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    Proofs,
    Counterexamples,
    Traces,
    Tools,
}

impl Artifact {
    fn dir(self) -> &'static str {
        match self {
            Self::Proofs => "proofs",
            Self::Counterexamples => "counterexamples",
            Self::Traces => "traces",
            Self::Tools => "tools",
        }
    }
}

/// UTC timestamp `YYYY-MM-DDTHH-MM-SSZ` without external crates.
pub fn timestamp(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{m:02}-{s:02}Z")
}

/// Base directory for evidence: `<root>/.proof-it` unless overridden.
pub fn evidence_base(root: &Path, out: Option<&Path>) -> Result<PathBuf> {
    match out {
        Some(o) => {
            std::fs::create_dir_all(o).map_err(|e| Error::io(o, e))?;
            Ok(o.to_path_buf())
        }
        None => {
            let base = root.join(".proof-it");
            ensure_real_dir(&base)?;
            // Keep evidence and caches out of version control by default.
            let gi = base.join(".gitignore");
            if !gi.exists() {
                let _ = std::fs::write(&gi, "runs/\ncache/\nchanges/\n");
            }
            Ok(base)
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunStore {
    pub id: String,
    pub dir: PathBuf,
}

impl RunStore {
    pub fn create(base: &Path) -> Result<Self> {
        let runs = base.join(RUNS);
        ensure_real_dir(&runs)?;
        let stamp = timestamp(SystemTime::now());
        let mut id = stamp.clone();
        let mut i = 1;
        while runs.join(&id).exists() {
            id = format!("{stamp}-{i}");
            i += 1;
        }
        let dir = runs.join(&id);
        std::fs::create_dir(&dir).map_err(|e| Error::io(&dir, e))?;
        for a in [Artifact::Proofs, Artifact::Counterexamples, Artifact::Traces, Artifact::Tools] {
            let d = dir.join(a.dir());
            std::fs::create_dir(&d).map_err(|e| Error::io(&d, e))?;
        }
        std::fs::write(runs.join("LATEST"), format!("{id}\n")).map_err(|e| Error::io(runs.join("LATEST"), e))?;
        Ok(Self { id, dir })
    }

    pub fn open(base: &Path, id: &str) -> Result<Self> {
        let runs = base.join(RUNS);
        let run_id = if id == "latest" {
            std::fs::read_to_string(runs.join("LATEST"))
                .map_err(|_| Error::Usage(format!("no previous run found in {}; run `proof-it assure` first", runs.display())))?
                .trim()
                .to_owned()
        } else {
            id.to_owned()
        };
        if run_id.is_empty() || !run_id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err(Error::Usage(format!("invalid run id {run_id:?}")));
        }
        let dir = runs.join(&run_id);
        if !dir.is_dir() {
            return Err(Error::Usage(format!("run {run_id} not found in {}", runs.display())));
        }
        Ok(Self { id: run_id, dir })
    }

    pub fn list(base: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(base.join(RUNS))
            .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// (absolute path, run-relative path) for a new artifact.
    pub fn artifact(&self, kind: Artifact, name: &str) -> Result<(PathBuf, String)> {
        let rel = format!("{}/{}", kind.dir(), safe_file_name(name, 140));
        Ok((safe_join(&self.dir, &rel)?, rel))
    }

    pub fn write_artifact(&self, kind: Artifact, name: &str, content: &str) -> Result<(PathBuf, String)> {
        let (abs, rel) = self.artifact(kind, name)?;
        std::fs::write(&abs, content).map_err(|e| Error::io(&abs, e))?;
        Ok((abs, rel))
    }

    pub fn write_json<T: Serialize>(&self, name: &str, v: &T) -> Result<PathBuf> {
        let p = safe_join(&self.dir, &safe_file_name(name, 120))?;
        let text = serde_json::to_string_pretty(v).map_err(|e| Error::Analysis(e.to_string()))?;
        std::fs::write(&p, text + "\n").map_err(|e| Error::io(&p, e))?;
        Ok(p)
    }

    pub fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let p = safe_join(&self.dir, name)?;
        let text = std::fs::read_to_string(&p).map_err(|e| Error::io(&p, e))?;
        serde_json::from_str(&text).map_err(|e| Error::Analysis(format!("{}: {e}", p.display())))
    }

    pub fn read_text(&self, rel: &str) -> Result<String> {
        let p = safe_join(&self.dir, rel)?;
        std::fs::read_to_string(&p).map_err(|e| Error::io(&p, e))
    }
}

/// Content-addressed proof cache: sha256(toolchain ‖ lean source) → accepted check.
/// Only ACCEPTED results are cached; a rejection is always recomputed.
#[derive(Debug, Clone)]
pub struct ProofCache {
    dir: Option<PathBuf>,
}

impl ProofCache {
    pub fn new(base: &Path, enabled: bool) -> Self {
        if !enabled {
            return Self { dir: None };
        }
        let cache = base.join("cache");
        let proofs = cache.join("proofs");
        let ok = ensure_real_dir(&cache).is_ok() && ensure_real_dir(&proofs).is_ok();
        Self { dir: ok.then_some(proofs) }
    }
    pub fn key(toolchain: &str, source: &str) -> String {
        let mut h = Sha256::new();
        h.update(toolchain.as_bytes());
        h.update([0u8]);
        h.update(source.as_bytes());
        hex(&h.finalize())
    }
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let p = self.dir.as_ref()?.join(format!("{key}.json"));
        serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
    }
    pub fn put<T: Serialize>(&self, key: &str, v: &T) {
        if let (Some(d), Ok(text)) = (&self.dir, serde_json::to_string(v)) {
            let _ = std::fs::write(d.join(format!("{key}.json")), text);
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00-00-00Z");
        assert_eq!(timestamp(UNIX_EPOCH + std::time::Duration::from_secs(1_791_403_544)), "2026-10-07T20-05-44Z");
    }

    #[test]
    fn refuses_symlinked_evidence_dir() {
        let d = tempfile::tempdir().expect("tmp");
        let target = tempfile::tempdir().expect("tmp2");
        std::os::unix::fs::symlink(target.path(), d.path().join(".proof-it")).expect("ln");
        assert!(evidence_base(d.path(), None).is_err());
    }

    #[test]
    fn run_lifecycle() {
        let d = tempfile::tempdir().expect("tmp");
        let base = evidence_base(d.path(), None).expect("base");
        let r = RunStore::create(&base).expect("create");
        r.write_json("summary.json", &serde_json::json!({"ok": true})).expect("write");
        let again = RunStore::open(&base, "latest").expect("open");
        assert_eq!(again.id, r.id);
        let (_, rel) = r.artifact(Artifact::Proofs, "../../escape.lean").expect("artifact");
        assert_eq!(rel, "proofs/escape.lean");
    }
}
