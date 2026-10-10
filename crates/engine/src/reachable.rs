//! Reachable vulnerable dependency APIs.
//!
//! A dependency advisory says a *package version* is vulnerable; whether the
//! application is exposed depends on whether it calls the affected function.
//! This check combines both: an installed version inside a known-vulnerable
//! range (from `package-lock.json`, else the lower bound of the `package.json`
//! range) **and** a call to the affected API in the service's code.
//!
//! The table is deliberately small and curated: each entry names its advisory,
//! the fixed versions and the vulnerable call. It works offline and complements
//! osv-scanner (package-level, needs network); it is not a replacement for it.

use proof_it_core::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

struct VulnApi {
    package: &'static str,
    /// Fixed versions per major line: a version is vulnerable if it is below the
    /// fixed version of its major line, or below the lowest listed line.
    fixed: &'static [(u64, u64, u64)],
    call: &'static str,
    rule: &'static str,
    severity: Severity,
    advisory: &'static str,
    what: &'static str,
    cwe: &'static [&'static str],
}

static TABLE: &[VulnApi] = &[
    VulnApi {
        package: "adm-zip",
        fixed: &[(0, 4, 11)],
        call: r"\.(extractAllTo|extractEntryTo)\s*\(",
        rule: "SEC-ZIP-SLIP",
        severity: Severity::High,
        advisory: "CVE-2018-1002204",
        what: "extracts archive entries without rejecting `../` paths (zip slip): an uploaded archive can write files anywhere",
        cwe: &["CWE-22"],
    },
    VulnApi {
        package: "decompress",
        fixed: &[(4, 2, 1)],
        call: r"\bdecompress\s*\(",
        rule: "SEC-ZIP-SLIP",
        severity: Severity::High,
        advisory: "CVE-2020-12265",
        what: "follows symlinks and `../` entries while extracting (zip slip)",
        cwe: &["CWE-22"],
    },
    VulnApi {
        package: "tar",
        fixed: &[(4, 4, 18), (5, 0, 10), (6, 1, 9)],
        call: r"\btar\.(x|extract)\s*\(",
        rule: "SEC-ZIP-SLIP",
        severity: Severity::High,
        advisory: "CVE-2021-37701, CVE-2021-37712",
        what: "can be made to write outside the extraction directory through crafted symlinks and paths",
        cwe: &["CWE-22", "CWE-59"],
    },
    VulnApi {
        package: "lodash",
        fixed: &[(4, 17, 12)],
        call: r"\b(_|lodash)\.(merge|mergeWith|defaultsDeep)\s*\(",
        rule: "SEC-PROTO-POLLUTION",
        severity: Severity::High,
        advisory: "CVE-2018-16487, CVE-2019-10744",
        what: "lets `__proto__`/`constructor` keys in merged objects modify Object.prototype",
        cwe: &["CWE-1321"],
    },
];

static VERSION: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(\d+)\.(\d+)\.(\d+)").expect("static regex")
});

fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let c = VERSION.captures(v)?;
    Some((c[1].parse().ok()?, c[2].parse().ok()?, c[3].parse().ok()?))
}

fn vulnerable(v: (u64, u64, u64), fixed: &[(u64, u64, u64)]) -> bool {
    match fixed.iter().find(|f| f.0 == v.0) {
        Some(f) => v < *f,
        // A major line older than every fixed line is vulnerable; newer ones are not.
        None => fixed.iter().all(|f| v.0 < f.0),
    }
}

/// Installed version: the lockfile's resolved version, else the lower bound of
/// the declared range (lower confidence: the lockfile may resolve higher).
fn installed(dir: &Path, package: &str) -> Option<((u64, u64, u64), bool)> {
    if let Ok(t) = std::fs::read_to_string(dir.join("package-lock.json"))
        && let Ok(j) = serde_json::from_str::<serde_json::Value>(&t)
    {
        let v = j["packages"][format!("node_modules/{package}")]["version"].as_str().or_else(|| j["dependencies"][package]["version"].as_str());
        if let Some(v) = v.and_then(parse) {
            return Some((v, true));
        }
    }
    let t = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let j: serde_json::Value = serde_json::from_str(&t).ok()?;
    let spec = ["dependencies", "devDependencies"].iter().find_map(|k| j[k][package].as_str())?;
    parse(spec).map(|v| (v, false))
}

/// `files`: (repo-relative path, text) of one service (directory with a package.json).
pub fn check(root: &Path, dir: &str, files: &[(&str, &str)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for api in TABLE {
        let Some((v, locked)) = installed(&root.join(dir), api.package) else {
            continue;
        };
        if !vulnerable(v, api.fixed) {
            continue;
        }
        #[allow(clippy::expect_used)]
        let call = Regex::new(api.call).expect("table regex");
        let import = format!("'{0}'|\"{0}\"", regex::escape(api.package));
        #[allow(clippy::expect_used)]
        let import = Regex::new(&import).expect("import regex");
        for (file, text) in files.iter().filter(|(_, t)| import.is_match(t)) {
            let Some(m) = call.find(text) else {
                continue;
            };
            let line = u32::try_from(text[..m.start()].matches('\n').count() + 1).unwrap_or(u32::MAX);
            let snippet = text.lines().nth(line as usize - 1).unwrap_or("").trim().chars().take(160).collect::<String>();
            let location = SourceLocation { file: (*file).to_owned(), line, column: None, end_line: None, snippet: Some(snippet) };
            let version = format!("{}.{}.{}", v.0, v.1, v.2);
            out.push(Finding {
                id: fingerprint(api.rule, Some(&location), api.package),
                rule_id: api.rule.to_owned(),
                property_id: Some("DATA-004".into()),
                title: format!("Vulnerable {} API is called", api.package),
                source: FindingSource::Security,
                severity: api.severity,
                confidence: if locked { Confidence::High } else { Confidence::Medium },
                description: format!(
                    "{} {version} ({}) is called here; this version {} ({}).",
                    api.package,
                    if locked { "from package-lock.json" } else { "lower bound of the package.json range" },
                    api.what,
                    api.advisory
                ),
                evidence: vec![Evidence::new(
                    EvidenceKind::StaticPattern,
                    format!("{} {version} is below the fixed version; vulnerable call `{}`", api.package, m.as_str().trim()),
                )],
                location: Some(location),
                recommendation: Some(format!("Upgrade {} to a fixed version ({}).", api.package, api.advisory)),
                cwe: api.cwe.iter().map(|c| (*c).to_owned()).collect(),
                suppressed: None,
                baseline: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ranges() {
        let tar = &[(4, 4, 18), (5, 0, 10), (6, 1, 9)];
        assert!(vulnerable((4, 4, 17), tar));
        assert!(!vulnerable((4, 4, 18), tar));
        assert!(vulnerable((6, 1, 0), tar));
        assert!(!vulnerable((7, 0, 0), tar));
        assert!(vulnerable((3, 2, 1), tar));
        assert!(vulnerable((0, 4, 7), &[(0, 4, 11)]));
        assert!(!vulnerable((0, 5, 0), &[(0, 4, 11)]), "0.5 is a newer line than the fixed 0.4.11");
    }

    #[test]
    fn requires_vulnerable_version_and_a_call() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(dir.path().join("package.json"), r#"{"dependencies":{"adm-zip":"0.4.7"}}"#).expect("write");
        let code = "var AdmZip = require('adm-zip');\nvar zip = AdmZip(file.data);\nzip.extractAllTo('/tmp/x', true);\n";
        let f = check(dir.path(), "", &[("routes/index.js", code)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SEC-ZIP-SLIP");
        assert_eq!(f[0].location.as_ref().map(|l| l.line), Some(3));
        // Imported but the vulnerable function is not called.
        assert!(check(dir.path(), "", &[("a.js", "var AdmZip = require('adm-zip');\nzip.getEntries();\n")]).is_empty());
        // Fixed version.
        std::fs::write(dir.path().join("package.json"), r#"{"dependencies":{"adm-zip":"^0.5.10"}}"#).expect("write");
        assert!(check(dir.path(), "", &[("routes/index.js", code)]).is_empty());
    }
}
