//! Personal data committed to the repository: CSV/JSON exports, database dumps
//! and database files.
//!
//! A repository is not a data store: everyone with read access (and every
//! clone, fork and CI cache) gets a copy, and deleting the file later does not
//! remove it from history. The check reports counts only — never the data.

use proof_it_core::paths::to_repo_path;
use proof_it_core::types::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const RULE_ID: &str = "SEC-COMMITTED-PERSONAL-DATA";

/// Distinct personal identifiers needed before a text export is reported.
const THRESHOLD: usize = 10;
/// Bytes read from each file (enough to recognise an export).
const HEAD_BYTES: u64 = 4 * 1024 * 1024;

#[allow(clippy::expect_used)]
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9._%+-]{1,64}@([a-z0-9-]+\.)+[a-z]{2,24}\b").expect("static regex"));
/// E.164-style phone numbers (`+` and 8–15 digits, optional separators).
#[allow(clippy::expect_used)]
static PHONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\+\d[\d\s().-]{7,18}\d").expect("static regex"));
/// Domains used for placeholder data.
#[allow(clippy::expect_used)]
static FAKE_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)@((\w+\.)*(example|test|invalid|localhost|domain|email|mail|foo|bar|acme)\.(com|org|net|io|test|local)|(\w+\.)*(test|invalid|example|localhost|local))$")
        .expect("static regex")
});
/// Column names that identify a person or their location (CSV/TSV header).
#[allow(clippy::expect_used)]
static PII_COLUMN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)e-?mail|phone|mobile|msisdn|address|street|postcode|zip_?code|\blat(itude)?\b|\blng\b|\blon(g|gitude)?\b|birth|\bdob\b|ssn|passport|national_?id|first_?name|last_?name|full_?name")
        .expect("static regex")
});

/// Paths of test data: reported with lower severity.
#[allow(clippy::expect_used)]
static TEST_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|mocks?|__mocks__|seeds?|examples?|samples?|testdata)(/|$)").expect("static regex"));
/// Files that are configuration, not data.
#[allow(clippy::expect_used)]
static CONFIG_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(package(-lock)?\.json|tsconfig[^/]*\.json|composer\.(json|lock)|[^/]*\.schema\.json|\.?eslintrc[^/]*|sarif[^/]*\.json)$")
        .expect("static regex")
});

enum Kind {
    Dump(&'static str),
    Export { emails: usize, phones: usize },
}

fn classify(head: &[u8], ext: &str) -> Option<Kind> {
    if head.starts_with(b"PGDMP") {
        return Some(Kind::Dump("PostgreSQL custom-format dump (pg_dump)"));
    }
    if head.starts_with(b"SQLite format 3\0") {
        return Some(Kind::Dump("SQLite database"));
    }
    let text = String::from_utf8_lossy(head);
    if ext == "sql" || ext == "dump" || ext == "bak" || ext == "backup" {
        if text.contains("-- PostgreSQL database dump") && text.contains("FROM stdin") {
            return Some(Kind::Dump("PostgreSQL plain-text dump with table data"));
        }
        if text.contains("-- MySQL dump") && text.contains("INSERT INTO") {
            return Some(Kind::Dump("MySQL dump with table data"));
        }
    }
    let emails: BTreeSet<String> = EMAIL.find_iter(&text).map(|m| m.as_str().to_ascii_lowercase()).filter(|e| !FAKE_DOMAIN.is_match(e)).collect();
    let phones: BTreeSet<String> = PHONE.find_iter(&text).map(|m| m.as_str().chars().filter(char::is_ascii_digit).collect::<String>()).collect();
    // A small export still counts when its header names personal-data columns and
    // at least one real identifier is present.
    let pii_columns =
        if matches!(ext, "csv" | "tsv") { text.lines().next().map_or(0, |h| h.split([',', '\t', ';']).filter(|c| PII_COLUMN.is_match(c)).count()) } else { 0 };
    let identifiers = emails.len() + phones.len();
    (emails.len() >= THRESHOLD || phones.len() >= THRESHOLD || (pii_columns >= 2 && identifiers >= 1))
        .then_some(Kind::Export { emails: emails.len(), phones: phones.len() })
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(HEAD_BYTES).read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in files {
        let rel = to_repo_path(root, path);
        if CONFIG_FILE.is_match(&rel) {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        let Some(head) = read_head(path) else {
            continue;
        };
        let Some(kind) = classify(&head, &ext) else {
            continue;
        };
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let test_data = TEST_PATH.is_match(&rel);
        let (what, evidence) = match kind {
            Kind::Dump(d) => (format!("a {d}"), format!("file signature: {d}; {size} bytes")),
            Kind::Export { emails, phones } => (
                format!(
                    "an export containing personal data ({emails} distinct email addresses, {phones} distinct phone numbers in the first {} MB)",
                    HEAD_BYTES / 1024 / 1024
                ),
                format!("{emails} distinct non-placeholder email addresses, {phones} distinct phone numbers; values not shown"),
            ),
        };
        let location = SourceLocation { file: rel.clone(), line: 1, column: None, end_line: None, snippet: None };
        out.push(Finding {
            id: fingerprint(RULE_ID, Some(&location), &rel),
            rule_id: RULE_ID.to_owned(),
            property_id: Some("DATA-002".into()),
            title: "Personal data committed to the repository".into(),
            source: FindingSource::Secrets,
            severity: if test_data { Severity::Low } else { Severity::High },
            confidence: if test_data { Confidence::Low } else { Confidence::High },
            location: Some(location),
            description: format!(
                "`{rel}` is {what}. Everyone with repository access, and every clone, fork and CI cache, has a copy; deleting the file does not remove it from git history."
            ),
            evidence: vec![Evidence::new(EvidenceKind::StaticPattern, evidence)],
            recommendation: Some(
                "Remove the file, add the pattern to .gitignore, and purge it from history (git filter-repo) if the data is real; keep exports in access-controlled storage. Check whether the exposure must be reported under your data-protection obligations."
                    .into(),
            ),
            cwe: vec!["CWE-359".into(), "CWE-538".into()],
            suppressed: None,
            baseline: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csv(domain: &str, n: usize, phones: bool) -> String {
        let mut s = "name,email,phone\n".to_owned();
        for i in 0..n {
            let phone = if phones { format!("+1415555{i:04}") } else { String::new() };
            s.push_str(&format!("User {i},user{i}@{domain},{phone}\n"));
        }
        s
    }

    #[test]
    fn exports_dumps_and_placeholders() {
        let dir = tempfile::tempdir().expect("tmp");
        let w = |name: &str, data: &[u8]| {
            let p = dir.path().join(name);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, data).expect("write");
            p
        };
        let files = vec![
            w("customers.csv", csv("gmail.com", 25, true).as_bytes()),
            w("placeholders.csv", csv("example.com", 25, false).as_bytes()),
            w("few.csv", "id,count\n1,a@gmail.com\n2,+14155550001\n".as_bytes()),
            w("small_export.csv", csv("gmail.com", 3, true).as_bytes()),
            w("schema_only.csv", "name,email,phone\n".as_bytes()),
            w("backup.dump", b"PGDMP\x01\x0e\x00binary"),
            w("tests/fixtures/users.csv", csv("gmail.com", 25, true).as_bytes()),
            w("package.json", csv("gmail.com", 25, true).as_bytes()),
            // A migration log that echoes customer records (missed before .txt/.log were checked).
            w("scripts/migration-log.txt", csv("gmail.com", 25, true).replace(',', " | ").as_bytes()),
            w("NOTES.txt", "Contact the maintainer at dev@gmail.com.\n".as_bytes()),
        ];
        let f = scan(dir.path(), &files);
        let by: Vec<(&str, Severity)> = f.iter().map(|x| (x.location.as_ref().map_or("", |l| l.file.as_str()), x.severity)).collect();
        assert_eq!(by.len(), 5, "{by:?}");
        assert!(by.contains(&("scripts/migration-log.txt", Severity::High)), "logs echoing customer data");
        assert!(by.contains(&("small_export.csv", Severity::High)), "PII header + real values");
        assert!(by.contains(&("customers.csv", Severity::High)));
        assert!(by.contains(&("backup.dump", Severity::High)));
        assert!(by.contains(&("tests/fixtures/users.csv", Severity::Low)));
        // Values are never echoed.
        let json = serde_json::to_string(&f).expect("json");
        assert!(!json.contains("user1@gmail.com") && !json.contains("+14155550001"));
    }
}
