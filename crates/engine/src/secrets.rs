//! Built-in secret scanner. The raw secret never leaves this module: findings
//! carry only a redacted prefix and a snippet with the secret replaced, so no
//! report format can leak it.

use proof_it_core::paths::to_repo_path;
use proof_it_core::redact::redact_secret;
use proof_it_core::types::{Confidence, Evidence, EvidenceKind, Finding, FindingSource, Severity, SourceLocation, fingerprint};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

struct Rule {
    id: &'static str,
    title: &'static str,
    re: Regex,
    severity: Severity,
    group: usize,
    min_entropy: Option<f64>,
}

#[allow(clippy::expect_used)]
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let r =
        |id, title, re: &str, severity, group, min_entropy| Rule { id, title, re: Regex::new(re).expect("static secret regex"), severity, group, min_entropy };
    vec![
        r("SECRET-AWS-ACCESS-KEY", "AWS access key id", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", Severity::High, 1, None),
        r("SECRET-AWS-SECRET-KEY", "AWS secret access key", r#"(?i)aws_?secret_?access_?key["'\s:=]+["']?([A-Za-z0-9/+=]{40})\b"#, Severity::Critical, 1, None),
        r(
            "SECRET-PRIVATE-KEY",
            "Private key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----([\s\S]{20,}?)-----END",
            Severity::Critical,
            1,
            None,
        ),
        r("SECRET-GITHUB-TOKEN", "GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,})\b", Severity::Critical, 1, None),
        r("SECRET-SLACK-TOKEN", "Slack token", r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b", Severity::High, 1, None),
        r("SECRET-STRIPE-KEY", "Stripe secret key", r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b", Severity::Critical, 1, None),
        r("SECRET-GOOGLE-API-KEY", "Google API key", r"\b(AIza[0-9A-Za-z_-]{35})\b", Severity::Medium, 1, None),
        r("SECRET-SENDGRID-KEY", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", Severity::High, 1, None),
        r("SECRET-OPENAI-KEY", "OpenAI API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b", Severity::High, 1, None),
        r("SECRET-ANTHROPIC-KEY", "Anthropic API key", r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b", Severity::High, 1, None),
        r(
            "SECRET-CONNECTION-STRING",
            "Connection string with password",
            r#"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^:\s/"'`]+:([^@\s"'`]{3,})@[^\s"'`]+"#,
            Severity::High,
            1,
            None,
        ),
        r("SECRET-JWT", "Hard-coded JSON Web Token", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", Severity::Medium, 1, None),
        r(
            "SECRET-GENERIC",
            "Hard-coded credential",
            r#"(?i)\b(?:password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token|client_?secret|jwt_?secret|private_?key)\b["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]"#,
            Severity::Medium,
            1,
            Some(3.0),
        ),
    ]
});

#[allow(clippy::expect_used)]
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(x+|\*+|changeme|change_me|password|secret|example|your[_-]?\w*|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|test\w*|dummy\w*|placeholder|sample|todo|none|null|undefined|process\.env.*|redacted|xxxx.*|\.\.\.+)$").expect("static regex")
});
#[allow(clippy::expect_used)]
static EXAMPLE_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(\.example|\.sample|\.template|example\.|\.md$|test|spec|fixture|mock)").expect("static regex"));

fn entropy(s: &str) -> f64 {
    let mut freq = std::collections::HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    freq.values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn re_signing(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    ["JWT", "SESSION", "SIGNING", "TOKEN_SECRET", "COOKIE", "HMAC", "APP_SECRET", "SECRET_KEY"].iter().any(|x| k.contains(x))
}

/// Rule ids produced by the built-in secret scanner.
pub fn rule_ids() -> Vec<&'static str> {
    RULES.iter().map(|r| r.id).collect()
}

/// `KEY=value` in a dotenv file, where the key names a credential. Values are often
/// unquoted and short (`JWT_SECRET=access`): a committed weak secret is worse, not better,
/// so no entropy threshold applies.
#[allow(clippy::expect_used)]
static DOTENV_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_?KEY|PRIVATE_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY)[A-Z0-9_]*)\s*=\s*["']?([^"'\s#]+)["']?\s*(?:#.*)?$"#)
        .expect("static regex")
});

fn is_dotenv(file: &str) -> bool {
    let name = file.rsplit('/').next().unwrap_or(file);
    name == ".env" || (name.starts_with(".env.") && !EXAMPLE_FILE.is_match(name)) || name.ends_with(".env")
}

pub fn scan_text(text: &str, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let example = EXAMPLE_FILE.is_match(file);
    if is_dotenv(file) {
        for cap in DOTENV_SECRET.captures_iter(text) {
            let (Some(key), Some(m)) = (cap.get(1), cap.get(2)) else {
                continue;
            };
            let secret = m.as_str();
            if PLACEHOLDER.is_match(secret) || secret.starts_with('$') {
                continue;
            }
            let line = u32::try_from(text[..m.start()].matches('\n').count() + 1).unwrap_or(u32::MAX);
            let redacted = redact_secret(secret);
            let snippet = format!("{}={redacted}", key.as_str());
            let location = SourceLocation { file: file.to_owned(), line, column: None, end_line: None, snippet: Some(snippet) };
            let weak = secret.chars().count() < 16 || entropy(secret) < 3.0;
            let signing = re_signing(key.as_str());
            out.push(Finding {
                id: fingerprint("SECRET-GENERIC", Some(&location), &redacted),
                rule_id: "SECRET-GENERIC".to_owned(),
                property_id: Some("DATA-002".into()),
                title: "Hard-coded credential".to_owned(),
                source: FindingSource::Secrets,
                severity: if weak && signing { Severity::High } else { Severity::Medium },
                confidence: Confidence::High,
                location: Some(location),
                description: format!(
                    "{} is committed in a dotenv file: {redacted}{}",
                    key.as_str(),
                    if weak && signing { " — and it is weak (short or low-entropy): tokens signed with it can be forged after an offline brute force" } else { "" }
                ),
                evidence: vec![Evidence::new(EvidenceKind::StaticPattern, format!("dotenv credential key; value redacted ({} chars)", secret.chars().count()))],
                recommendation: Some(
                    "Do not commit .env files (add them to .gitignore, commit a .env.example with placeholders); rotate the value; signing secrets need ≥256 random bits.".into(),
                ),
                cwe: if weak && signing { vec!["CWE-798".into(), "CWE-521".into()] } else { vec!["CWE-798".into()] },
                suppressed: None,
                baseline: None,
            });
        }
    }
    for rule in RULES.iter() {
        if rule.id == "SECRET-GENERIC" && is_dotenv(file) {
            continue; // covered by the dotenv rule above
        }
        for cap in rule.re.captures_iter(text) {
            let Some(m) = cap.get(rule.group).or_else(|| cap.get(0)) else {
                continue;
            };
            let secret = m.as_str();
            if PLACEHOLDER.is_match(secret) || rule.min_entropy.is_some_and(|e| entropy(secret) < e) {
                continue;
            }
            let line = u32::try_from(text[..m.start()].matches('\n').count() + 1).unwrap_or(u32::MAX);
            let line_text = text.lines().nth(line as usize - 1).unwrap_or("");
            let redacted = redact_secret(secret);
            let snippet: String = line_text.replace(secret, &redacted).trim().chars().take(160).collect();
            let location = SourceLocation { file: file.to_owned(), line, column: None, end_line: None, snippet: Some(snippet) };
            let severity = if example && rule.severity != Severity::Critical { Severity::Low } else { rule.severity };
            out.push(Finding {
                id: fingerprint(rule.id, Some(&location), &redacted),
                rule_id: rule.id.to_owned(),
                property_id: Some("DATA-002".into()),
                title: rule.title.to_owned(),
                source: FindingSource::Secrets,
                severity,
                confidence: if rule.id == "SECRET-GENERIC" { Confidence::Medium } else { Confidence::High },
                location: Some(location),
                description: format!("Potential {} committed to the repository: {redacted}", rule.title.to_lowercase()),
                evidence: vec![Evidence::new(EvidenceKind::StaticPattern, format!("matched {}; value redacted ({} chars)", rule.id, secret.chars().count()))],
                recommendation: Some("Revoke/rotate the credential, remove it from git history, and load it from the environment or a secret manager.".into()),
                cwe: vec!["CWE-798".into()],
                suppressed: None,
                baseline: None,
            });
        }
    }
    out
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in files {
        let Ok(bytes) = std::fs::read(f) else {
            continue;
        };
        if bytes.contains(&0) {
            continue; // binary
        }
        let text = String::from_utf8_lossy(&bytes);
        out.extend(scan_text(&text, &to_repo_path(root, f)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_unquoted_and_weak_secrets() {
        let f = scan_text("PORT=80\nJWT_SECRET=access\nAPI_KEY=${FROM_VAULT}\nDB_PASSWORD=changeme\nSQL_PASSWORD=mysecretpassword # local\n", ".env");
        let keys: Vec<&str> = f.iter().filter_map(|x| x.location.as_ref()?.snippet.as_deref()).collect();
        assert_eq!(f.len(), 2, "{keys:?}");
        assert!(keys[0].starts_with("JWT_SECRET=") && !keys[0].contains("access"));
        assert_eq!(f[0].severity, Severity::High, "weak signing secret");
        assert!(scan_text("JWT_SECRET=access\n", ".env.example").is_empty());
    }

    #[test]
    fn redacts_and_ignores_placeholders() {
        let key = "AKIAZ7XQ3MNBV2LKPQRS";
        let f = scan_text(&format!("const k = '{key}';\nconst p = 'changeme';"), "src/a.ts");
        assert_eq!(f.len(), 1);
        let json = serde_json::to_string(&f).unwrap_or_default();
        assert!(!json.contains(key), "secret leaked into finding JSON");
        assert!(json.contains("AKIA"));
    }

    #[test]
    fn connection_string_password_is_redacted() {
        let f = scan_text("DATABASE_URL=postgres://app:S3cr3tP4ssw0rd!@db:5432/x", ".env");
        assert_eq!(f.len(), 1);
        assert!(!serde_json::to_string(&f).unwrap_or_default().contains("S3cr3tP4ssw0rd"));
    }
}
