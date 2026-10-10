//! Checks that need more than one file: template output escaping, and
//! application-level security configuration (headers, CSRF, rate limiting).
//!
//! These are heuristics with stated confidence, not proofs: they look for the
//! presence of well-known protections and report their absence.

use proof_it_core::facts::ProgramFacts;
use proof_it_core::paths::to_repo_path;
use proof_it_core::types::*;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Rule ids produced by the application-level checks.
pub const RULE_IDS: &[&str] = &["SEC-XSS-TEMPLATE", "SEC-NO-SECURITY-HEADERS", "SEC-CSRF", "SEC-NO-RATE-LIMIT"];

#[allow(clippy::expect_used)]
fn re(s: &str) -> Regex {
    Regex::new(s).expect("static regex")
}

static EJS_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"<%-\s*([^%]{1,80})%>"));
static HBS_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"\{\{\{\s*([^}]{1,80})\}\}\}"));
static PUG_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"(!=\s*\S|!\{[^}]{1,80}\})"));
static NJK_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"(\|\s*safe\b|\{%\s*autoescape\s+false\s*%\})"));
static VUE_RAW: LazyLock<Regex> = LazyLock::new(|| re(r#"v-html\s*=\s*"([^"]{1,80})""#));
static SVELTE_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"\{@html\s+([^}]{1,80})\}"));

#[allow(clippy::too_many_arguments)]
fn finding(rule: &str, title: &str, sev: Severity, conf: Confidence, location: SourceLocation, desc: String, rec: &str, prop: &str, cwe: &[&str]) -> Finding {
    Finding {
        id: fingerprint(rule, Some(&location), ""),
        rule_id: rule.into(),
        property_id: Some(prop.into()),
        title: title.into(),
        source: FindingSource::Security,
        severity: sev,
        confidence: conf,
        evidence: vec![Evidence::new(EvidenceKind::StaticPattern, location.snippet.clone().unwrap_or_default())],
        location: Some(location),
        description: desc,
        recommendation: Some(rec.into()),
        cwe: cwe.iter().map(|c| (*c).to_owned()).collect(),
        suppressed: None,
        baseline: None,
    }
}

fn loc_at(file: &str, text: &str, offset: usize) -> SourceLocation {
    let line = u32::try_from(text[..offset].matches('\n').count() + 1).unwrap_or(u32::MAX);
    let snippet: String = text.lines().nth(line as usize - 1).unwrap_or("").trim().chars().take(160).collect();
    SourceLocation { file: file.into(), line, column: None, end_line: None, snippet: Some(snippet) }
}

/// Unescaped output in server/client templates.
pub fn templates(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        let re: &Regex = match ext.as_str() {
            "ejs" => &EJS_RAW,
            "hbs" | "handlebars" => &HBS_RAW,
            "pug" | "jade" => &PUG_RAW,
            "njk" => &NJK_RAW,
            "html" => &NJK_RAW,
            "vue" => &VUE_RAW,
            "svelte" => &SVELTE_RAW,
            _ => continue,
        };
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let rel = to_repo_path(root, f);
        for m in re.find_iter(&text) {
            // `<%- include(...) %>` renders a partial, not a value.
            if ext == "ejs" && m.as_str().trim_start_matches("<%-").trim_start().starts_with("include") {
                continue;
            }
            let l = loc_at(&rel, &text, m.start());
            out.push(finding(
                "SEC-XSS-TEMPLATE",
                "Unescaped template output",
                Severity::Medium,
                Confidence::Medium,
                l,
                format!(
                    "`{}` writes a value into HTML without escaping; if any part comes from users it is an XSS sink.",
                    m.as_str().chars().take(60).collect::<String>()
                ),
                "Use the escaping form (<%= %>, {{ }}, #{}) unless the value is trusted, sanitised HTML.",
                "API-003",
                &["CWE-79"],
            ));
        }
    }
    out
}

static APP_CREATE: LazyLock<Regex> = LazyLock::new(|| re(r"\b(express|fastify|koa|Koa)\s*\(\s*\)|new\s+Koa\s*\(|NestFactory\.create"));
// `.post('/x', …)` and `.route('/x').get(…).post(…)`.
static MUTATING_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"\.(post|put|patch|delete)\s*\(\s*['"`]/|\.route\s*\(\s*['"`][^'"`]+['"`]\s*\)(\s*\.\w+\s*\([^;]*?\))*?\s*\.(post|put|patch|delete)\s*\("#)
});
static AUTH_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"\.(post|put)\s*\(\s*['"`][^'"`]*(login|signin|sign-in|authenticate|auth/|token|password|otp|verify|reset)[^'"`]*['"`]|\.route\s*\(\s*['"`][^'"`]*(login|signin|sign-in|authenticate|auth/|token|password|otp|verify|reset)[^'"`]*['"`]\s*\)\s*\.(post|put)\s*\("#,
    )
});
// Cookie-carried authentication: session middleware, or a token/session cookie set or read by hand.
static COOKIE_SESSION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)express-session|cookie-session|cookieSession\s*\(|\bsession\s*\(\s*\{|res\.cookie\s*\(\s*['"`][^'"`]*(token|auth|session|jwt|sid)|set-cookie['"]\s*,\s*[`'"][^`'"]*(token|auth|session|jwt|sid)\w*=|req\.cookies\s*(\.|\[\s*['"`])\w*(token|auth|session|jwt|sid)|req\.headers\.cookie"#,
    )
});
static CSRF: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"csurf|csrf-csrf|lusca|tiny-csrf|@fastify/csrf|csrfProtection|doubleCsrf|(?i:sameSite\s*:\s*['"](strict|lax)['"]|SameSite=(Strict|Lax))"#)
});
/// A handler that verifies a password (a credential oracle that can be brute-forced).
static PASSWORD_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(bcrypt|bcryptjs|argon2|scrypt)\.(compare|verify)\w*\s*\(|\b(comparePassword|verifyPassword|checkPassword|validatePassword|isValidPassword|passwordMatches)\s*\(",
    )
});
static LIMITER_NAME: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)limit|throttl|slowdown|brute"));
static GLOBAL_LIMITER: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\.(use|register)\s*\(\s*[^)]*(limit|throttl|slowdown|brute)"));
static HELMET: LazyLock<Regex> = LazyLock::new(|| re(r#"\bhelmet\b|@fastify/helmet|koa-helmet|Content-Security-Policy"#));
static RATE_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    re(r"express-rate-limit|rate-limiter-flexible|express-slow-down|@nestjs/throttler|@fastify/rate-limit|koa-ratelimit|rateLimit\s*\(|RateLimiter|limiter")
});

/// Remove `//` and `/* */` comments so commented-out protections do not count.
/// (Approximate: a `//` inside a string literal also truncates the line, which can
/// only make a protection look absent, i.e. produce a finding, never hide one.)
pub fn strip_comments(text: &str) -> String {
    static BLOCK: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)/\*.*?\*/"));
    static LINE: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)(^|[^:\\])//.*$"));
    let t = BLOCK.replace_all(text, "");
    LINE.replace_all(&t, "$1").into_owned()
}

/// Application-level configuration per service (directory containing a package.json).
pub fn app_config(root: &Path, facts: &ProgramFacts) -> Vec<Finding> {
    // Group sources by their nearest package.json directory (each service in a monorepo).
    let stripped: Vec<(String, String)> = facts.texts.iter().map(|(f, t)| (f.clone(), strip_comments(t))).collect();
    let mut apps: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
    for (file, text) in &stripped {
        let mut dir = Path::new(file).parent().map(Path::to_path_buf).unwrap_or_default();
        loop {
            if root.join(&dir).join("package.json").exists() || dir.as_os_str().is_empty() {
                break;
            }
            dir = dir.parent().map(Path::to_path_buf).unwrap_or_default();
        }
        apps.entry(dir.display().to_string()).or_default().push((file.as_str(), text.as_str()));
    }
    let mut out = Vec::new();
    for (dir, files) in apps {
        out.extend(crate::reachable::check(root, &dir, &files));
        let Some((app_file, app_text, offset)) = files.iter().find_map(|(f, t)| APP_CREATE.find(t).map(|m| (*f, *t, m.start()))) else {
            continue;
        };
        // A protection counts only if the code uses it: an installed-but-unused
        // dependency (or a commented-out line) protects nothing.
        let any = |r: &Regex| files.iter().any(|(_, t)| r.is_match(t));
        let l = loc_at(app_file, app_text, offset);
        let svc = if dir.is_empty() { "the application".to_owned() } else { format!("`{dir}`") };
        if !any(&HELMET) {
            out.push(finding(
                "SEC-NO-SECURITY-HEADERS",
                "Security headers not configured",
                Severity::Low,
                Confidence::Medium,
                l.clone(),
                format!("{svc} creates an HTTP app without helmet or an equivalent: no CSP, HSTS, frame-ancestors or nosniff headers."),
                "Add helmet (or set the headers at the edge proxy and document it).",
                "API-007",
                &["CWE-693", "CWE-1021"],
            ));
        }
        let mutating = files.iter().any(|(_, t)| MUTATING_ROUTE.is_match(t));
        if any(&COOKIE_SESSION) && mutating && !any(&CSRF) {
            out.push(finding(
                "SEC-CSRF",
                "No CSRF protection for cookie-authenticated state changes",
                Severity::Medium,
                Confidence::Medium,
                l.clone(),
                format!(
                    "{svc} authenticates with cookies and exposes state-changing routes, but no CSRF token middleware or SameSite cookie policy was found."
                ),
                "Use SameSite=Lax/Strict session cookies and a CSRF token for cookie-authenticated forms.",
                "API-007",
                &["CWE-352"],
            ));
        }
        if let Some((f, t, m)) = files.iter().find_map(|(f, t)| AUTH_ROUTE.find(t).map(|m| (*f, *t, m)))
            && !any(&RATE_LIMIT)
        {
            out.push(finding(
                "SEC-NO-RATE-LIMIT",
                "Authentication endpoints without rate limiting",
                Severity::Medium,
                Confidence::Medium,
                loc_at(f, t, m.start()),
                format!("{svc} exposes authentication routes but no rate-limiting library or limiter was found: credentials and OTPs can be brute-forced."),
                "Rate-limit login/OTP/password-reset routes per account and per IP (or document the edge limiter).",
                "AUTH-005",
                &["CWE-307", "CWE-770"],
            ));
        } else if any(&RATE_LIMIT) && !any(&GLOBAL_LIMITER) {
            // The service rate-limits some routes: every other route that verifies a
            // password is an unthrottled credential oracle.
            out.extend(unthrottled_password_routes(facts, &files, &svc));
        }
    }
    out
}

/// Routes whose handler verifies a password but whose registration has no limiter.
fn unthrottled_password_routes(facts: &ProgramFacts, files: &[(&str, &str)], svc: &str) -> Vec<Finding> {
    let in_app = |f: &str| files.iter().any(|(x, _)| *x == f);
    let text_of = |f: &str| facts.texts.iter().find(|(x, _)| x == f).map(|(_, t)| t.as_str());
    let body_text = |h: &proof_it_core::facts::HandlerFact| -> Option<String> {
        let t = text_of(&h.location.file)?;
        let (a, b) = (h.location.line as usize, h.location.end_line? as usize);
        Some(t.lines().skip(a.saturating_sub(1)).take(b + 1 - a.min(b)).collect::<Vec<_>>().join("\n"))
    };
    let resolve = |name: &str| -> Option<&proof_it_core::facts::HandlerFact> {
        let c: Vec<_> =
            facts.modules.iter().flat_map(|m| m.handler_bodies.iter()).filter(|b| b.function == name || b.function.rsplit('.').next() == Some(name)).collect();
        if c.len() == 1 { Some(c[0]) } else { None }
    };
    let mut out = Vec::new();
    for m in facts.modules.iter().filter(|m| in_app(&m.file)) {
        for r in &m.route_refs {
            let Some(body) = r.args.iter().filter_map(|a| a.name.as_deref()).filter_map(resolve).find(|b| b.params.len() < 3) else {
                continue;
            };
            if r.args.iter().any(|a| LIMITER_NAME.is_match(&a.text)) || !body_text(body).is_some_and(|t| PASSWORD_CHECK.is_match(&t)) {
                continue;
            }
            out.push(finding(
                "SEC-NO-RATE-LIMIT",
                "Password verification endpoint without rate limiting",
                Severity::Medium,
                Confidence::High,
                r.location.clone(),
                format!(
                    "{} {} verifies a password ({}) but, unlike other routes in {svc}, has no rate limiter: it can be used to brute-force credentials.",
                    r.method, r.path, body.function
                ),
                "Apply the same per-account and per-IP limiter as the login route.",
                "AUTH-005",
                &["CWE-307"],
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_patterns() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("a.ejs"), "<%- include('h') %>\n<p><%- output.searchTerm %></p><p><%= safe %></p>").expect("w");
        std::fs::write(d.path().join("b.hbs"), "{{{body}}} {{escaped}}").expect("w");
        let f = templates(d.path(), &[d.path().join("a.ejs"), d.path().join("b.hbs")]);
        assert_eq!(f.len(), 2, "{f:#?}");
        assert_eq!(f[0].location.as_ref().map(|l| l.line), Some(2));
    }

    #[test]
    fn app_level() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("package.json"), r#"{"dependencies":{"express":"4","express-session":"1","helmet":"7","csurf":"1"}}"#).expect("w");
        let text = "const app = express();\napp.use(session({ secret: s }));\napp.post('/login', h);\napp.post('/transfer', h);\n";
        let facts = ProgramFacts { modules: vec![], texts: vec![("server.js".into(), text.into())], parse_errors: vec![] };
        let rules: Vec<String> = app_config(d.path(), &facts).into_iter().map(|f| f.rule_id).collect();
        assert!(rules.contains(&"SEC-NO-SECURITY-HEADERS".to_owned()));
        assert!(rules.contains(&"SEC-CSRF".to_owned()));
        assert!(rules.contains(&"SEC-NO-RATE-LIMIT".to_owned()));
        let commented =
            "const app = express();\n// app.use(helmet());\n/* const csrf = require('csurf'); */\napp.use(session({ secret: s }));\napp.post('/login', h);\n";
        let facts = ProgramFacts { modules: vec![], texts: vec![("server.js".into(), commented.into())], parse_errors: vec![] };
        let rules: Vec<String> = app_config(d.path(), &facts).into_iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&"SEC-NO-SECURITY-HEADERS".to_owned()) && rules.contains(&"SEC-CSRF".to_owned()),
            "commented-out protections must not count: {rules:?}"
        );
        let safe =
            "const app = express();\napp.use(helmet());\napp.use(rateLimit({}));\napp.use(session({ cookie: { sameSite: 'lax' } }));\napp.post('/login', h);\n";
        let facts = ProgramFacts { modules: vec![], texts: vec![("server.js".into(), safe.into())], parse_errors: vec![] };
        assert!(app_config(d.path(), &facts).is_empty());
    }
}
