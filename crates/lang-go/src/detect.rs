//! Go security detectors. Rule ids, titles, CWEs and advice come from the shared
//! catalogue (`proof_it_core::rules`), so a rule means the same in every language.

use crate::taint::{Roles, Scope, Taint, args, passthrough_functions};
use crate::{Src, descendants};
use proof_it_core::rules::rule;
use proof_it_core::types::{Confidence, Evidence, EvidenceKind, Finding, FindingSource, fingerprint};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use tree_sitter::Node;

macro_rules! re {
    ($p:literal) => {{
        static R: LazyLock<Regex> = LazyLock::new(|| {
            #[allow(clippy::expect_used)]
            Regex::new($p).expect("static regex")
        });
        &*R
    }};
}

struct Out<'a, 's> {
    src: &'a Src<'s>,
    findings: Vec<Finding>,
    seen: BTreeSet<(&'static str, u32)>,
}

impl Out<'_, '_> {
    fn report(&mut self, rule_id: &'static str, at: Node<'_>, description: String, confidence: Confidence, evidence: Vec<Evidence>) {
        let Some(r) = rule(rule_id) else { return };
        let location = self.src.loc(at);
        if !self.seen.insert((r.id, location.line)) {
            return;
        }
        self.findings.push(Finding {
            id: fingerprint(r.id, Some(&location), ""),
            rule_id: r.id.to_owned(),
            property_id: Some(r.property.to_owned()),
            title: r.title.to_owned(),
            source: FindingSource::Security,
            severity: r.severity,
            confidence,
            location: Some(location),
            description,
            evidence,
            recommendation: Some(r.recommendation.to_owned()),
            cwe: r.cwe.iter().map(|c| (*c).to_owned()).collect(),
            suppressed: None,
            baseline: None,
        });
    }
}

fn flow(t: &Taint, sink: &str) -> Vec<Evidence> {
    vec![
        Evidence::new(EvidenceKind::StaticPattern, format!("request data `{}` (line {}) flows into {sink}", t.source, t.line))
            .with_details(serde_json::json!({ "source": t.source, "source_line": t.line })),
    ]
}

fn pattern(s: impl Into<String>) -> Vec<Evidence> {
    vec![Evidence::new(EvidenceKind::StaticPattern, s)]
}

pub fn run(src: &Src<'_>, root: Node<'_>) -> Vec<Finding> {
    let passthrough = passthrough_functions(src, root);
    let mut out = Out { src, findings: vec![], seen: BTreeSet::new() };
    for kind in ["function_declaration", "method_declaration", "func_literal"] {
        for f in descendants(root, kind) {
            let Some(body) = f.child_by_field_name("body") else { continue };
            let roles = Roles::of(src, f.child_by_field_name("parameters"));
            let mut s = Scope::new(src, roles, &passthrough);
            s.propagate(body);
            for call in descendants(body, "call_expression") {
                sinks(&s, &mut out, call);
            }
        }
    }
    config_checks(src, root, &mut out);
    out.findings
}

fn sinks(s: &Scope<'_, '_>, out: &mut Out<'_, '_>, call: Node<'_>) {
    let Some(f) = call.child_by_field_name("function") else { return };
    let callee = s.src.compact(f);
    let method = callee.rsplit('.').next().unwrap_or("").to_owned();
    let a = args(call);
    let receiver_is_request = s.roles.contexts.iter().chain(s.roles.requests.iter()).any(|r| callee.starts_with(&format!("{r}.")));

    // SQL: database/sql, sqlx, gorm Raw/Exec/Where/Order. The query is the first
    // string argument (after a context for the *Context variants).
    if !receiver_is_request
        && re!(r"^(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Get|Select|GetContext|SelectContext|Queryx|QueryRowx|NamedExec|NamedQuery|MustExec|Raw|Where|Order|Having|Joins|Group)$").is_match(&method)
    {
        // A leading context argument (`ctx`, `r.Context()`, `context.Background()`) is
        // skipped: database/sql's *Context methods and pgx's methods both take one.
        let ctx_first = a.first().is_some_and(|x| re!(r"(?i)^(ctx|c|context\.\w+\(\)|\w+\.Context\(\))$").is_match(&s.src.compact(*x)));
        let qi = usize::from(method.ends_with("Context") || ctx_first);
        let qi = if matches!(method.as_str(), "Get" | "Select" | "GetContext" | "SelectContext") { qi + 1 } else { qi };
        if let Some(q) = a.get(qi).copied() {
            let text = s.src.of(q);
            let sql_like = re!(r"(?i)\b(select|insert|update|delete|where|order by|from)\b").is_match(text) || !matches!(method.as_str(), "Get" | "Select" | "GetContext" | "SelectContext");
            if s.dynamic_string(q) && sql_like {
                match s.taint(q) {
                    Some(t) => out.report("SEC-SQLI", call, format!("Request data is concatenated into SQL passed to {callee}()."), Confidence::High, flow(&t, &format!("{callee}()"))),
                    None if !matches!(method.as_str(), "Where" | "Order" | "Group" | "Having" | "Joins") => out.report(
                        "SEC-DYNAMIC-SQL",
                        call,
                        format!("SQL passed to {callee}() is built from runtime values; no request source was traced to it in this function."),
                        Confidence::Medium,
                        pattern("dynamic SQL string"),
                    ),
                    None => {}
                }
            }
        }
    }

    // OS command injection.
    if re!(r"^exec\.(Command|CommandContext)$").is_match(&callee) {
        let base = usize::from(callee.ends_with("Context"));
        let prog = a.get(base).map(|p| s.src.of(*p).trim_matches('"').to_owned()).unwrap_or_default();
        let shell = re!(r"^(/bin/|/usr/bin/)?(sh|bash|zsh|dash|cmd(\.exe)?|powershell(\.exe)?)$").is_match(&prog);
        let tainted_prog = a.get(base).and_then(|p| s.taint(*p));
        let tainted_shell_arg = if shell { a.iter().skip(base + 1).find_map(|x| s.taint(*x)) } else { None };
        if let Some(t) = tainted_prog.or(tainted_shell_arg) {
            out.report("SEC-CMDI", call, format!("Request data reaches a shell command via {callee}()."), Confidence::High, flow(&t, &format!("{callee}()")));
        }
    }

    // Path traversal.
    let path_arg = match callee.as_str() {
        "os.Open" | "os.OpenFile" | "os.ReadFile" | "os.WriteFile" | "os.Create" | "os.Remove" | "os.RemoveAll" | "os.Mkdir" | "os.MkdirAll" | "os.ReadDir"
        | "os.Stat" | "ioutil.ReadFile" | "ioutil.WriteFile" | "ioutil.ReadDir" => Some(0),
        "http.ServeFile" => Some(2),
        _ if s.roles.contexts.iter().any(|c| {
            callee == format!("{c}.File") || callee == format!("{c}.SendFile") || callee == format!("{c}.Attachment") || callee == format!("{c}.FileAttachment")
        }) =>
        {
            Some(0)
        }
        _ => None,
    };
    if let Some(i) = path_arg
        && let Some(t) = a.get(i).and_then(|p| s.taint(*p))
    {
        out.report(
            "SEC-PATH-TRAVERSAL",
            call,
            format!("Request data selects a filesystem path in {callee}()."),
            Confidence::High,
            flow(&t, &format!("{callee}()")),
        );
    }

    // SSRF.
    let url_arg = match callee.as_str() {
        "http.Get" | "http.Head" | "http.Post" | "http.PostForm" => Some(0),
        "http.NewRequest" => Some(1),
        "http.NewRequestWithContext" => Some(2),
        _ if re!(r"(?i)client\.(Get|Head|Post|PostForm)$").is_match(&callee) => Some(0),
        _ => None,
    };
    if let Some(i) = url_arg
        && let Some(t) = a.get(i).and_then(|p| s.taint(*p))
    {
        out.report(
            "SEC-SSRF",
            call,
            format!("Request data chooses the destination of an outbound request ({callee})."),
            Confidence::High,
            flow(&t, &format!("{callee}()")),
        );
    }

    // Open redirect.
    let redirect_arg = if callee == "http.Redirect" {
        Some(2)
    } else if s.roles.contexts.iter().any(|c| callee == format!("{c}.Redirect")) {
        Some(a.len().saturating_sub(1))
    } else {
        None
    };
    if let Some(i) = redirect_arg
        && let Some(t) = a.get(i).and_then(|p| s.taint(*p))
    {
        out.report("SEC-OPEN-REDIRECT", call, "Redirect target comes from request data.".into(), Confidence::High, flow(&t, &format!("{callee}()")));
    }

    // Reflected XSS: request data written raw to the response, or marked as safe HTML.
    let writes_html = |w: &str| s.roles.writers.iter().any(|x| x == w);
    let xss = match callee.as_str() {
        "fmt.Fprintf" | "fmt.Fprint" | "fmt.Fprintln" | "io.WriteString" => {
            a.first().is_some_and(|w| writes_html(s.src.of(*w))).then(|| a.iter().skip(1).find_map(|x| s.taint(*x))).flatten()
        }
        "template.HTML" | "template.JS" | "template.URL" => a.first().and_then(|x| s.taint(*x)),
        _ if s.roles.writers.iter().any(|w| callee == format!("{w}.Write")) => a.first().and_then(|x| s.taint(*x)),
        _ => None,
    };
    let json_response = re!(r#"application/json"#).is_match(s.src.text);
    if let Some(t) = xss
        && (!json_response || callee.starts_with("template."))
    {
        out.report(
            "SEC-XSS",
            call,
            format!("Request data is written into an HTTP response without HTML encoding ({callee})."),
            Confidence::Medium,
            flow(&t, &format!("{callee}()")),
        );
    }

    // Server-side template injection: a template parsed from request data.
    if method == "Parse"
        && re!(r"template\.(New|Must)").is_match(&callee)
        && let Some(t) = a.first().and_then(|x| s.taint(*x))
    {
        out.report("SEC-SSTI", call, "A template is parsed from request data.".into(), Confidence::High, flow(&t, "template.Parse()"));
    }

    // Weak hashing of passwords.
    if re!(r"^(md5|sha1)\.(Sum|New)$").is_match(&callee) {
        let ctx = format!("{} {}", s.src.of(call), call.parent().map(|p| s.src.of(p)).unwrap_or(""));
        if re!(r"(?i)pass(word|wd)?|pwd|secret|credential").is_match(&ctx) {
            out.report(
                "SEC-WEAK-HASH",
                call,
                format!("{} is used to hash a password or secret.", callee.split('.').next().unwrap_or("")),
                Confidence::High,
                pattern(s.src.of(call).to_owned()),
            );
        }
    }
}

fn config_checks(src: &Src<'_>, root: Node<'_>, out: &mut Out<'_, '_>) {
    // tls.Config{InsecureSkipVerify: true}
    for k in descendants(root, "keyed_element") {
        let t = src.compact(k);
        if t == "InsecureSkipVerify:true" {
            out.report(
                "SEC-TLS-DISABLED",
                k,
                "TLS certificate verification is disabled (InsecureSkipVerify: true).".into(),
                Confidence::High,
                pattern("InsecureSkipVerify: true"),
            );
        }
    }
    // math/rand used to produce a security value.
    let imports_math_rand = descendants(root, "import_spec").iter().any(|i| src.of(*i).contains("\"math/rand"));
    let imports_crypto_rand = descendants(root, "import_spec").iter().any(|i| src.of(*i).contains("\"crypto/rand\""));
    if imports_math_rand && !imports_crypto_rand {
        for call in descendants(root, "call_expression") {
            let callee = call.child_by_field_name("function").map(|f| src.compact(f)).unwrap_or_default();
            if !re!(r"^rand\.(Int|Intn|Int31|Int31n|Int63|Int63n|Read|Uint32|Uint64|Float64|Perm)$").is_match(&callee) {
                continue;
            }
            // The value is security-relevant if it lands in a token/secret/OTP-like name.
            let mut n = call;
            let mut ctx = String::new();
            for _ in 0..4 {
                if let Some(p) = n.parent() {
                    n = p;
                    if matches!(p.kind(), "short_var_declaration" | "assignment_statement" | "var_spec" | "function_declaration" | "return_statement") {
                        ctx = src.of(p).chars().take(300).collect();
                        break;
                    }
                }
            }
            let enclosing_fn = {
                let mut m = call;
                while let Some(p) = m.parent() {
                    m = p;
                    if p.kind() == "function_declaration" {
                        break;
                    }
                }
                m.child_by_field_name("name").map(|x| src.of(x).to_owned()).unwrap_or_default()
            };
            if re!(r"(?i)token|secret|otp|nonce|salt|password|session|apikey|api_key|reset|verification|csrf").is_match(&format!("{ctx} {enclosing_fn}")) {
                out.report(
                    "SEC-INSECURE-RANDOM",
                    call,
                    "math/rand is used to produce a security value; it is predictable.".into(),
                    Confidence::High,
                    pattern(callee),
                );
            }
        }
    }
}
