//! Security detectors for TypeScript/JavaScript.
//!
//! Taint analysis is intra-procedural and flow-insensitive within a function:
//! a local is tainted if any assignment to it derives from a request source.
//! Simple and predictable: every finding states which source reached which
//! sink. Interprocedural flows are left to the Semgrep adapter (documented).

use crate::expr::{Aliases, Conv, binding_names, inner, lit_str};
use crate::text::Source;
use oxc::ast::ast::*;
use oxc::ast_visit::{Visit, walk};
use oxc::span::{GetSpan, Span};
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator, LogicalOperator};
use oxc::syntax::scope::ScopeFlags;
use proof_it_core::types::{Confidence, Evidence, EvidenceKind, Finding, FindingSource, Severity, fingerprint};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub cwe: &'static [&'static str],
    pub recommendation: &'static str,
    pub property: &'static str,
}

macro_rules! rule {
    ($id:literal, $title:literal, $sev:ident, [$($cwe:literal),*], $rec:literal, $prop:literal) => {
        Rule { id: $id, title: $title, severity: Severity::$sev, cwe: &[$($cwe),*], recommendation: $rec, property: $prop }
    };
}

pub static RULES: &[Rule] = &[
    rule!("SEC-SQLI", "SQL injection", Critical, ["CWE-89"], "Use parameterised queries; pass request values as bind parameters.", "DATA-001"),
    rule!("SEC-DYNAMIC-SQL", "SQL built from runtime values", Medium, ["CWE-89"], "Use placeholders for values; allow-list identifiers.", "DB-001"),
    rule!("SEC-CMDI", "OS command injection", Critical, ["CWE-78"], "Use execFile/spawn with an argument array and no shell.", "DATA-001"),
    rule!("SEC-CODE-INJECTION", "Code injection (eval)", Critical, ["CWE-95"], "Never evaluate request data as code.", "DATA-001"),
    rule!("SEC-EVAL", "Use of eval / new Function", Medium, ["CWE-95"], "Remove dynamic code evaluation.", "DATA-001"),
    rule!("SEC-NOSQLI", "NoSQL operator injection", High, ["CWE-943"], "Cast query values to primitives; reject objects in query fields.", "DATA-001"),
    rule!("SEC-PATH-TRAVERSAL", "Path traversal", High, ["CWE-22"], "Resolve against a base directory and verify the result stays inside it.", "DATA-003"),
    rule!("SEC-SSRF", "Server-side request forgery", High, ["CWE-918"], "Allow-list outbound destinations.", "API-001"),
    rule!("SEC-OPEN-REDIRECT", "Open redirect", Medium, ["CWE-601"], "Redirect only to relative paths or an allow-list.", "API-002"),
    rule!("SEC-XSS", "Cross-site scripting", High, ["CWE-79"], "HTML-encode output or use an auto-escaping template engine.", "API-003"),
    rule!("SEC-DESERIALIZE", "Unsafe deserialization", High, ["CWE-502"], "Use a data-only parser (JSON.parse, yaml safe load).", "DATA-004"),
    rule!(
        "SEC-PROTO-POLLUTION",
        "Prototype pollution via deep merge",
        Medium,
        ["CWE-1321"],
        "Copy allow-listed fields; reject __proto__/constructor keys.",
        "DATA-004"
    ),
    rule!("SEC-MASS-ASSIGN", "Mass assignment", High, ["CWE-915"], "Persist only allow-listed fields from the request body.", "AUTHZ-003"),
    rule!(
        "SEC-JWT-DECODE",
        "JWT claims read without signature verification",
        High,
        ["CWE-347"],
        "Use jwt.verify with a key and an algorithms allow-list.",
        "AUTH-003"
    ),
    rule!("SEC-JWT-ALG-NONE", "JWT 'none' algorithm accepted", Critical, ["CWE-347"], "Restrict algorithms to the expected signing algorithm.", "AUTH-003"),
    rule!("SEC-JWT-IGNORE-EXPIRATION", "JWT expiry ignored", High, ["CWE-613"], "Remove ignoreExpiration.", "AUTH-002"),
    rule!("SEC-JWT-NO-EXPIRY", "JWT issued without expiry", Medium, ["CWE-613"], "Pass expiresIn when signing.", "AUTH-002"),
    rule!("SEC-WEAK-HASH", "Weak hash for secrets", High, ["CWE-916", "CWE-328"], "Use argon2id/scrypt/bcrypt for passwords.", "CRYPTO-001"),
    rule!("SEC-DEPRECATED-CIPHER", "Deprecated cipher API without IV", High, ["CWE-327"], "Use createCipheriv with AES-GCM and a random IV.", "CRYPTO-001"),
    rule!("SEC-INSECURE-RANDOM", "Math.random used for a security value", High, ["CWE-338"], "Use crypto.randomBytes / randomInt / randomUUID.", "CRYPTO-002"),
    rule!(
        "SEC-TLS-DISABLED",
        "TLS certificate validation disabled",
        High,
        ["CWE-295"],
        "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0.",
        "CRYPTO-003"
    ),
    rule!("SEC-TIMING-COMPARE", "Non-constant-time secret comparison", Low, ["CWE-208"], "Use crypto.timingSafeEqual.", "CRYPTO-004"),
    rule!("SEC-CORS", "Credentialed CORS with wildcard/reflected origin", Medium, ["CWE-942"], "Use an explicit origin allow-list.", "API-004"),
    rule!("SEC-COOKIE-FLAGS", "Session cookie without httpOnly/secure", Medium, ["CWE-1004", "CWE-614"], "Set httpOnly: true and secure: true.", "SESS-001"),
    rule!(
        "SEC-REDOS",
        "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
        Medium,
        ["CWE-1333"],
        "Remove nested quantifiers (e.g. (a+)+); use a linear-time regex engine (re2) for untrusted input.",
        "API-005"
    ),
    rule!(
        "SEC-REGEX-INJECTION",
        "Regular expression built from request data",
        High,
        ["CWE-1333", "CWE-625"],
        "Escape user input before building a RegExp, or match literally.",
        "API-005"
    ),
    rule!("SEC-XXE", "XML external entity processing enabled", High, ["CWE-611"], "Never enable noent/dtdload when parsing untrusted XML.", "DATA-004"),
    rule!(
        "SEC-TEMPLATE-AUTOESCAPE",
        "Template auto-escaping disabled",
        High,
        ["CWE-79", "CWE-116"],
        "Keep auto-escaping on; mark individual trusted values as safe instead.",
        "API-003"
    ),
    rule!(
        "SEC-XSS-TEMPLATE",
        "Unescaped template output",
        Medium,
        ["CWE-79"],
        "Use the escaping form (<%= %>, {{ }}) unless the value is trusted HTML.",
        "API-003"
    ),
    rule!(
        "SEC-SSTI",
        "Server-side template injection",
        Critical,
        ["CWE-1336", "CWE-94"],
        "Never compile templates from request data; pass data as template variables.",
        "DATA-001"
    ),
    rule!(
        "SEC-HARDCODED-SESSION-SECRET",
        "Hard-coded session/cookie signing secret",
        High,
        ["CWE-798", "CWE-321"],
        "Load the secret from the environment or a secret manager and rotate it.",
        "SESS-001"
    ),
    rule!(
        "SEC-ERROR-DISCLOSURE",
        "Internal error details sent to the client",
        Low,
        ["CWE-209"],
        "Log the error server-side; send a generic message and a correlation id.",
        "API-006"
    ),
    rule!(
        "SEC-LOG-INJECTION",
        "Request data written to logs unsanitised",
        Low,
        ["CWE-117"],
        "Encode CR/LF in logged values or use structured logging fields.",
        "API-006"
    ),
    rule!(
        "SEC-JWT-ALG-UNPINNED",
        "JWT verified without pinning algorithms",
        Low,
        ["CWE-347", "CWE-327"],
        "Pass algorithms: ['RS256'] (or the expected algorithm) to every verify call.",
        "AUTH-003"
    ),
    rule!(
        "SEC-ZIP-SLIP",
        "Archive entry path used for file writes (zip slip)",
        High,
        ["CWE-22"],
        "Resolve entry names against the target directory and reject paths that escape it.",
        "DATA-003"
    ),
    rule!(
        "SEC-UNRESTRICTED-UPLOAD",
        "File upload without type or size restrictions",
        Medium,
        ["CWE-434", "CWE-400"],
        "Configure a fileFilter (allow-listed MIME types/extensions) and limits.fileSize; store uploads outside the web root.",
        "DATA-003"
    ),
    rule!(
        "SEC-XPATH-INJECTION",
        "XPath injection",
        High,
        ["CWE-643"],
        "Use parameterised XPath (variable resolvers) or allow-list the value; never concatenate request data into an expression.",
        "DATA-001"
    ),
    rule!(
        "SEC-XML-INJECTION",
        "XML/SOAP injection",
        Medium,
        ["CWE-91"],
        "Build XML with a serializer (xmlbuilder2, js2xmlparser) or escape &, <, >, \", ' in interpolated values.",
        "DATA-001"
    ),
    rule!(
        "SEC-GRAPHQL-INTROSPECTION",
        "GraphQL introspection enabled explicitly",
        Low,
        ["CWE-200"],
        "Disable introspection (and the playground/debug) outside development.",
        "API-007"
    ),
    rule!(
        "SEC-HEADER-INJECTION",
        "Request data in a response header",
        Low,
        ["CWE-113", "CWE-644"],
        "Allow-list header values; never reflect request data into headers such as Location or Set-Cookie.",
        "API-006"
    ),
    rule!(
        "SEC-SPOOFABLE-CLIENT-IP",
        "Rate limit or block keyed on a spoofable client IP",
        Medium,
        ["CWE-348", "CWE-290"],
        "Use req.ip with `trust proxy` set to the exact number of proxy hops (or the proxy subnets); never read X-Forwarded-For directly.",
        "AUTH-005"
    ),
    rule!(
        "SEC-PLAINTEXT-PASSWORD",
        "Passwords stored in plaintext",
        High,
        ["CWE-256", "CWE-916"],
        "Store passwords with argon2id, scrypt or bcrypt and verify with the library's compare function; never query by password.",
        "CRYPTO-001"
    ),
    rule!(
        "SEC-SESSION-DEFAULTS",
        "Session cookie relies on insecure defaults",
        Low,
        ["CWE-614", "CWE-1275"],
        "Configure cookie: { secure: true, httpOnly: true, sameSite: 'lax' }.",
        "SESS-001"
    ),
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

static SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies|files?|url|originalUrl|path|hostname|ip)\b|^event\.(body|queryStringParameters|pathParameters|headers)\b").expect("static regex")
});
static SANITIZER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(parseInt|parseFloat|Number|Boolean|encodeURIComponent|escape\w*|\w+Escape\w*|sanitize\w*|validator\.\w+|path\.basename|basename|Math\.\w+|uuidValidate|isUUID|z\.\w+|DOMPurify\.sanitize|xss|he\.encode)$").expect("static regex")
});
static SQL_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*[`'\x22]?\s*(SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE|MERGE)\b").expect("static regex"));
static HTTP_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(axios|http|https|undici|superagent|needle|request|got|node_fetch|nodeFetch|ky|phin|httpClient|client)\.(get|post|put|delete|del|patch|request|head|stream|fetch)$").expect("static regex")
});
static NESTED_QUANTIFIER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\((?:\?:)?(?:[^()\\]|\\.)*[+*}]\)[+*{]").expect("static regex"));
static TEMPLATE_ENGINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(ejs|pug|jade|nunjucks|swig|Handlebars|handlebars|hbs|mustache|Mustache|_|lodash|dot|doT|dust|eta|liquid)\.(render|compile|renderString|template|compileFile)$").expect("static regex")
});
/// Request headers a client can set freely to claim any IP address.
static CLIENT_IP_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(headers\s*\[\s*['"`]|headers\.|\.(get|header)\(\s*['"`])(x-forwarded-for|x-real-ip|true-client-ip|cf-connecting-ip|x-client-ip|forwarded)\b"#,
    )
    .expect("static regex")
});
static SECRET_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)token|secret|otp|password|passwd|nonce|salt|session|apikey|api_key|reset|verification|code|key").expect("static regex"));
static SECRET_CMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(signature|hmac|digest|apiKey|api_key|webhookSecret|secret|csrfToken)\b").expect("static regex"));

#[derive(Clone, Debug)]
struct Taint {
    source: String,
    line: u32,
}

struct Scope<'c, 's> {
    src: &'c Source<'s>,
    aliases: Aliases,
    tainted: HashMap<String, Taint>,
    /// Locals initialised with a string built from runtime values (`const q = "..." + x`).
    dynamic_strings: BTreeSet<String>,
    /// Calls to local functions with tainted arguments: (callee, argument index, taint).
    tainted_calls: Vec<(String, usize, Taint)>,
    /// Locals holding archive entry names (`const fileName = entry.path`).
    entry_paths: BTreeSet<String>,
    /// Locals holding a client-supplied IP header (`req.headers['x-forwarded-for']`).
    spoofable_ips: BTreeSet<String>,
    /// Locals holding a whole request object (`const profile = req.body`).
    request_objects: BTreeSet<String>,
    /// Variables initialised with an object literal anywhere in the file: name → source
    /// text (all initialisers joined), so `cors(corsOptions)` sees the options.
    objects: &'c HashMap<String, String>,
    /// Functions in this file whose return value carries a tainted argument
    /// (whatever their name says — `sanitizeInput(x) { return x }` is one).
    passthrough: &'c BTreeSet<String>,
    file_text: &'s str,
    out: Vec<Finding>,
}

impl<'c, 's> Scope<'c, 's> {
    /// Source text of an argument; an identifier bound to an object literal in this file
    /// resolves to that literal.
    fn arg_text(&self, e: &Expression<'_>) -> String {
        if let Expression::Identifier(id) = inner(e)
            && let Some(t) = self.objects.get(id.name.as_str())
        {
            return t.clone();
        }
        self.src.slice(e.span()).to_owned()
    }

    /// `req.body` / `req.query` / `req.params` itself (not one field), or a copy of it.
    fn is_request_object(&self, e: &Expression<'_>) -> bool {
        match inner(e) {
            Expression::Identifier(id) => self.request_objects.contains(id.name.as_str()),
            Expression::ObjectExpression(o) => {
                o.properties.iter().any(|p| matches!(p, ObjectPropertyKind::SpreadProperty(sp) if self.is_request_object(&sp.argument)))
            }
            Expression::CallExpression(c) if re!(r"^(Object\.assign|_\.(merge|assign|extend))$").is_match(&self.conv().callee(c)) => {
                c.arguments.iter().filter_map(|a| a.as_expression()).any(|a| self.is_request_object(a))
            }
            e => self.conv().raw_path(e).is_some_and(|p| re!(r"^(req|request|ctx\.request)\.(body|query|params)$").is_match(&p)),
        }
    }

    fn conv(&self) -> Conv<'_, 's> {
        Conv::new(self.src, &self.aliases)
    }

    fn taint(&self, e: &Expression<'_>) -> Option<Taint> {
        let e = inner(e);
        if let Some(p) = self.conv().raw_path(e)
            && SOURCE.is_match(&p)
        {
            return Some(Taint { source: p, line: self.src.line_col(e.span().start).0 });
        }
        match e {
            Expression::Identifier(id) => self.tainted.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(m) => self.taint(&m.object),
            Expression::ComputedMemberExpression(m) => self.taint(&m.object),
            Expression::ChainExpression(_) => self.conv().raw_path(e).and_then(|p| self.tainted.get(p.split(['.', '[']).next().unwrap_or("")).cloned()),
            Expression::CallExpression(c) => {
                let callee = self.conv().callee(c);
                // Local functions are judged by their code, not their name.
                if self.passthrough.contains(&callee) {
                    return self.first_tainted(&c.arguments);
                }
                if SANITIZER.is_match(&callee) {
                    return None;
                }
                // `req.get('origin')`, `req.header('x-forwarded-for')`, `req.param('id')`
                if re!(r"^(req|request|ctx)\.(get|header|param)$").is_match(&callee) {
                    return Some(Taint { source: crate::text::collapse(self.src.slice(c.span), 60), line: self.src.line_col(c.span.start).0 });
                }
                if let Some(m) = c.callee.get_inner_expression().as_member_expression()
                    && m.static_property_name().is_some_and(|n| {
                        matches!(
                            n,
                            "trim"
                                | "trimStart"
                                | "trimEnd"
                                | "toLowerCase"
                                | "toUpperCase"
                                | "toString"
                                | "concat"
                                | "replace"
                                | "replaceAll"
                                | "slice"
                                | "substring"
                                | "substr"
                                | "padStart"
                                | "padEnd"
                                | "split"
                                | "join"
                                | "normalize"
                                | "match"
                                | "matchAll"
                        )
                    })
                {
                    return self.taint(m.object()).or_else(|| self.first_tainted(&c.arguments));
                }
                // `re.exec(x)` returns the matched parts of x.
                if let Some(m) = c.callee.get_inner_expression().as_member_expression()
                    && m.static_property_name() == Some("exec")
                    && (matches!(inner(m.object()), Expression::RegExpLiteral(_))
                        || matches!(inner(m.object()), Expression::Identifier(id) if re!(r"(?i)re(gex|gexp)?$|pattern").is_match(id.name.as_str())))
                {
                    return self.first_tainted(&c.arguments);
                }
                // Accessors on parsed request documents (`xmlDoc.get('//user').text()`).
                if let Some(m) = c.callee.get_inner_expression().as_member_expression()
                    && m.static_property_name().is_some_and(|n| {
                        matches!(n, "get" | "text" | "attr" | "getAttribute" | "find" | "at" | "item" | "value" | "valueOf" | "toJSON" | "nodeValue")
                    })
                    && let Some(t) = self.taint(m.object())
                {
                    return Some(t);
                }
                if matches!(
                    callee.as_str(),
                    "String"
                        | "JSON.stringify"
                        | "decodeURIComponent"
                        | "decodeURI"
                        | "path.join"
                        | "path.resolve"
                        | "join"
                        | "resolve"
                        | "url.resolve"
                        | "Buffer.from"
                        | "atob"
                        | "JSON.parse"
                        | "parseXml"
                        | "parseXmlString"
                        | "libxml.parseXml"
                        | "libxmljs.parseXml"
                        | "libxmljs2.parseXml"
                        | "querystring.parse"
                        | "qs.parse"
                ) {
                    return self.first_tainted(&c.arguments);
                }
                None
            }
            Expression::TemplateLiteral(t) => t.expressions.iter().find_map(|x| self.taint(x)),
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => self.taint(&b.left).or_else(|| self.taint(&b.right)),
            Expression::LogicalExpression(l) if l.operator != LogicalOperator::And => self.taint(&l.left).or_else(|| self.taint(&l.right)),
            Expression::ConditionalExpression(c) => self.taint(&c.consequent).or_else(|| self.taint(&c.alternate)),
            Expression::ObjectExpression(o) => o.properties.iter().find_map(|p| match p {
                ObjectPropertyKind::ObjectProperty(op) => self.taint(&op.value),
                ObjectPropertyKind::SpreadProperty(sp) => self.taint(&sp.argument),
            }),
            Expression::ArrayExpression(a) => a.elements.iter().filter_map(|x| x.as_expression()).find_map(|x| self.taint(x)),
            _ => None,
        }
    }

    fn first_tainted(&self, args: &[Argument<'_>]) -> Option<Taint> {
        args.iter().filter_map(|a| a.as_expression()).find_map(|a| self.taint(a))
    }

    /// A string built from non-constant parts (template with expressions, `+` with a non-literal).
    fn dynamic_string(e: &Expression<'_>) -> bool {
        match inner(e) {
            Expression::TemplateLiteral(t) => !t.expressions.is_empty(),
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                let lit = |x: &Expression<'_>| matches!(inner(x), Expression::StringLiteral(_) | Expression::NumericLiteral(_));
                !(lit(&b.left) && lit(&b.right))
                    && (Self::dynamic_string(&b.left)
                        || Self::dynamic_string(&b.right)
                        || matches!(inner(&b.left), Expression::StringLiteral(_))
                        || matches!(inner(&b.right), Expression::StringLiteral(_)))
            }
            _ => false,
        }
    }

    fn finding(&mut self, rule_id: &'static str, at: Span, description: String, confidence: Confidence, evidence: Vec<Evidence>, severity: Option<Severity>) {
        let Some(r) = rule(rule_id) else { return };
        let location = self.src.loc(at);
        self.out.push(Finding {
            id: fingerprint(r.id, Some(&location), ""),
            rule_id: r.id.to_owned(),
            property_id: Some(r.property.to_owned()),
            title: r.title.to_owned(),
            source: FindingSource::Security,
            severity: severity.unwrap_or(r.severity),
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

    fn flow(&self, t: &Taint, sink: &str) -> Vec<Evidence> {
        vec![
            Evidence::new(EvidenceKind::StaticPattern, format!("request data `{}` (line {}) flows into {sink}", t.source, t.line))
                .with_details(serde_json::json!({ "source": t.source, "source_line": t.line })),
        ]
    }

    fn pattern(summary: impl Into<String>) -> Vec<Evidence> {
        vec![Evidence::new(EvidenceKind::StaticPattern, summary)]
    }

    fn call(&mut self, c: &CallExpression<'_>) {
        if let Expression::Identifier(id) = c.callee.get_inner_expression() {
            for (i, a) in c.arguments.iter().enumerate() {
                if let Some(t) = a.as_expression().and_then(|x| self.taint(x)) {
                    self.tainted_calls.push((id.name.as_str().to_owned(), i, t));
                }
            }
        }
        let callee = self.conv().callee(c);
        let method =
            c.callee.get_inner_expression().as_member_expression().and_then(|m| m.static_property_name()).map_or_else(|| callee.clone(), |m| m.to_string());
        let args: Vec<&Expression<'_>> = c.arguments.iter().filter_map(|a| a.as_expression()).collect();
        let a0 = args.first().copied();
        let a0_text = a0.map(|a| self.src.slice(a.span()).to_owned()).unwrap_or_default();

        // SQL
        if let Some(a0) = a0
            && matches!(
                method.as_str(),
                "query"
                    | "raw"
                    | "execute"
                    | "exec"
                    | "$queryRawUnsafe"
                    | "$executeRawUnsafe"
                    | "unsafe"
                    | "prepare"
                    | "all"
                    | "get"
                    | "run"
                    | "whereRaw"
                    | "joinRaw"
                    | "orderByRaw"
                    | "havingRaw"
            )
        {
            let sqlish = SQL_TEXT.is_match(&a0_text) || re!(r"Raw|query|unsafe|execute").is_match(&method);
            let via_local = matches!(inner(a0), Expression::Identifier(id) if self.dynamic_strings.contains(id.name.as_str()));
            if sqlish && (Self::dynamic_string(a0) || via_local) {
                if let Some(t) = self.taint(a0) {
                    let ev = self.flow(&t, &format!("{callee}()"));
                    self.finding("SEC-SQLI", c.span, format!("Request data is concatenated into SQL passed to {callee}()."), Confidence::High, ev, None);
                } else if SQL_TEXT.is_match(&a0_text) || method.contains("Unsafe") || method.contains("Raw") {
                    self.finding(
                        "SEC-DYNAMIC-SQL",
                        c.span,
                        format!("SQL passed to {callee}() is built from runtime values; no request source was traced to it in this function."),
                        Confidence::Medium,
                        Self::pattern("dynamic SQL string"),
                        None,
                    );
                }
            }
        }
        // Command injection
        let shell_true = args.iter().any(|a| re!(r"shell\s*:\s*true").is_match(self.src.slice(a.span())));
        if (matches!(callee.as_str(), "exec" | "execSync" | "child_process.exec" | "child_process.execSync" | "cp.exec" | "shell.exec")
            || (matches!(method.as_str(), "spawn" | "spawnSync" | "execFile") && shell_true))
            && let Some(t) = a0.and_then(|a| self.taint(a)).or_else(|| self.first_tainted(&c.arguments))
        {
            let ev = self.flow(&t, &format!("{callee}()"));
            self.finding("SEC-CMDI", c.span, format!("Request data reaches a shell command via {callee}()."), Confidence::High, ev, None);
        }
        // Expression evaluators that execute code (mathjs.eval in vulnerable versions, safe-eval, vm2, notevil)
        if let Some(a0) = a0
            && re!(r"^(math|mathjs)\.(eval|evaluate|compile|parse)$|^(safeEval|safe_eval|staticEval|notevil|vm2\.run|vm\.run)$").is_match(&callee)
            && let Some(t) = self.taint(a0)
        {
            let ev = self.flow(&t, &format!("{callee}()"));
            self.finding(
                "SEC-CODE-INJECTION",
                c.span,
                format!("Request data is evaluated by the expression engine {callee}(); several versions allow escaping to arbitrary code execution."),
                Confidence::Medium,
                ev,
                Some(Severity::High),
            );
        }
        // eval
        if let Some(a0) = a0
            && (callee == "eval" || matches!(callee.as_str(), "vm.runInNewContext" | "vm.runInThisContext" | "vm.runInContext" | "runInNewContext"))
        {
            if let Some(t) = self.taint(a0) {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding("SEC-CODE-INJECTION", c.span, format!("Request data is evaluated as code by {callee}()."), Confidence::High, ev, None);
            } else if callee == "eval" && !matches!(inner(a0), Expression::StringLiteral(_)) {
                self.finding("SEC-EVAL", c.span, "Dynamic code evaluation with eval().".into(), Confidence::Medium, Self::pattern("eval of non-literal"), None);
            }
        }
        // Path traversal
        if let Some(a0) = a0 {
            let fs_obj = re!(r"^(fs\w*|fsp|fs\.promises|promises|res|reply|response|fse)\.").is_match(&callee);
            if fs_obj
                && matches!(
                    method.as_str(),
                    "readFile"
                        | "readFileSync"
                        | "createReadStream"
                        | "writeFile"
                        | "writeFileSync"
                        | "createWriteStream"
                        | "unlink"
                        | "unlinkSync"
                        | "rm"
                        | "rmSync"
                        | "readdir"
                        | "sendFile"
                        | "download"
                        | "appendFile"
                        | "stat"
                        | "access"
                        | "open"
                )
            {
                let rooted = args.get(1).is_some_and(|x| re!(r"root\s*:").is_match(self.src.slice(x.span())));
                if let (Some(t), false) = (self.taint(a0), rooted) {
                    let ev = self.flow(&t, &format!("{callee}()"));
                    self.finding("SEC-PATH-TRAVERSAL", c.span, format!("Request data selects a filesystem path in {callee}()."), Confidence::High, ev, None);
                }
            }
        }
        // SSRF
        if let Some(a0) = a0 {
            let net = matches!(callee.as_str(), "fetch" | "got" | "request" | "needle" | "phin" | "bent" | "wget") || HTTP_CLIENT.is_match(&callee);
            if net && let Some(t) = self.taint(a0) {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding(
                    "SEC-SSRF",
                    c.span,
                    format!("Request data chooses the destination of an outbound request ({callee})."),
                    Confidence::High,
                    ev,
                    None,
                );
            }
        }
        // Rate limiting / blocking keyed on a client-supplied IP header.
        if matches!(method.as_str(), "get" | "set" | "has" | "incr" | "incrby" | "increment" | "hit" | "consume" | "add" | "push" | "delete" | "del" | "expire")
            && let Some(m) = c.callee.get_inner_expression().as_member_expression()
            && re!(r"(?i)limit|rate|attempt|throttl|brute|block|ban|hits|requests|counter|failed").is_match(self.src.slice(m.object().span()))
            && let Some(a) = a0
            && (matches!(inner(a), Expression::Identifier(id) if self.spoofable_ips.contains(id.name.as_str())) || CLIENT_IP_HEADER.is_match(&a0_text))
            // One finding per function: every Map call on the same key is the same defect.
            && !self.out.iter().any(|f| f.rule_id == "SEC-SPOOFABLE-CLIENT-IP")
        {
            self.finding(
                "SEC-SPOOFABLE-CLIENT-IP",
                c.span,
                format!(
                    "{callee}() keys a rate-limit or block list on a client-supplied IP header: rotating X-Forwarded-For gives every request a fresh bucket."
                ),
                Confidence::High,
                Self::pattern(crate::text::collapse(self.src.slice(c.span), 80)),
                None,
            );
        }
        // `app.set('trust proxy', true)`: req.ip becomes the left-most (client-supplied) hop.
        if a0.and_then(|a| lit_str(inner(a))) == Some("trust proxy")
            && (method == "enable" || method == "set" && matches!(args.get(1).map(|a| inner(a)), Some(Expression::BooleanLiteral(b)) if b.value))
        {
            self.finding(
                "SEC-SPOOFABLE-CLIENT-IP",
                c.span,
                "`trust proxy` is `true`: Express trusts every X-Forwarded-For hop, so req.ip (used by rate limiters and logs) is whatever the client sends."
                    .into(),
                Confidence::High,
                Self::pattern("trust proxy = true"),
                Some(Severity::Low),
            );
        }
        // Template locals from the whole request object: the client sets engine options
        // (`layout`, `settings`, `cache`, ejs `outputFunctionName`, ...).
        if re!(r"^(res|reply|response|ctx)\.render$").is_match(&callee)
            && let Some(locals) = args.get(1)
            && self.is_request_object(locals)
        {
            self.finding(
                "SEC-SSTI",
                c.span,
                format!(
                    "The whole request object is passed as template locals to {callee}(): the client can add engine options such as `layout` (local file inclusion) or ejs `settings`/`outputFunctionName` (code execution)."
                ),
                Confidence::High,
                Self::pattern(crate::text::collapse(self.src.slice(c.span), 80)),
                None,
            );
        }
        // Plaintext passwords: a query that matches the stored password against the
        // submitted one only works if passwords are stored unhashed.
        if matches!(
            method.as_str(),
            "find" | "findOne" | "findFirst" | "findUnique" | "findMany" | "findAll" | "where" | "count" | "countDocuments" | "exists" | "findOneAndUpdate"
        ) && let Some(Expression::ObjectExpression(o)) = a0.map(inner)
        {
            let props = |o: &ObjectExpression<'_>| -> Vec<(String, Span, bool)> {
                o.properties
                    .iter()
                    .filter_map(|p| match p {
                        ObjectPropertyKind::ObjectProperty(op) => {
                            Some((op.key.static_name().map(|k| k.into_owned()).unwrap_or_default(), op.span, self.taint(&op.value).is_some()))
                        }
                        ObjectPropertyKind::SpreadProperty(_) => None,
                    })
                    .collect()
            };
            let mut all = props(o);
            // Prisma/Sequelize: { where: { ... } }
            for p in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(op) = p
                    && op.key.static_name().is_some_and(|k| k == "where")
                    && let Expression::ObjectExpression(w) = inner(&op.value)
                {
                    all.extend(props(w));
                }
            }
            if let Some((k, sp, _)) = all.iter().find(|(k, _, t)| *t && re!(r"(?i)^(password|passwd|pass|pwd|user_?password)$").is_match(k)) {
                self.finding(
                    "SEC-PLAINTEXT-PASSWORD",
                    *sp,
                    format!("The submitted password is used as a query filter (`{k}`) in {callee}(): passwords are stored in plaintext (or with a deterministic hash) instead of a salted password hash."),
                    Confidence::High,
                    Self::pattern(format!("{k} matched against request data")),
                    None,
                );
            }
        }
        if let Some(a0) = a0
            && SQL_TEXT.is_match(&a0_text)
            && re!(r"(?i)\b(password|passwd|pwd)\s*=\s*(\$\d+|\?|:\w+|'?\$\{|'\s*\+)").is_match(&a0_text)
        {
            self.finding(
                "SEC-PLAINTEXT-PASSWORD",
                a0.span(),
                format!("SQL passed to {callee}() compares the password column with a submitted value: passwords are stored in plaintext (or with a deterministic hash)."),
                Confidence::High,
                Self::pattern("password = <parameter> in SQL"),
                None,
            );
        }
        // Open redirect
        if re!(r"^(res|reply|response|ctx)\.redirect$").is_match(&callee)
            && let Some(last) = args.last()
            && let Some(t) = self.taint(last)
        {
            let ev = self.flow(&t, "res.redirect()");
            self.finding("SEC-OPEN-REDIRECT", c.span, "Redirect target comes from request data.".into(), Confidence::High, ev, None);
        }
        // XPath injection: request data concatenated into an XPath expression.
        if let Some(a0) = a0
            && (callee.starts_with("xpath.")
                || matches!(method.as_str(), "evaluate" | "select" | "select1" | "selectNodes" | "selectSingleNode")
                || matches!(method.as_str(), "get" | "find") && re!(r"(?i)(doc|xml|dom)\w*\.(get|find)$").is_match(&callee))
            && Self::dynamic_string(a0)
            && re!(r#"['"`]\s*/|\[@|/\w+\["#).is_match(&a0_text)
            && let Some(t) = self.taint(a0)
        {
            let ev = self.flow(&t, &format!("the XPath expression of {callee}()"));
            self.finding(
                "SEC-XPATH-INJECTION",
                c.span,
                format!(
                    "Request data is concatenated into the XPath expression evaluated by {callee}(); a value like `' or '1'='1` changes which nodes match."
                ),
                Confidence::High,
                ev,
                None,
            );
        }
        // Response headers: reflected CORS origin, request data in headers.
        if re!(r"^(res|reply|response|ctx)\.(set|header|setHeader|append|writeHead|set_header)$").is_match(&callee)
            && let (Some(name), Some(value)) = (a0.and_then(|a| lit_str(inner(a))), args.get(1))
        {
            let name = name.to_ascii_lowercase();
            let value_text = self.src.slice(value.span());
            if name == "access-control-allow-origin" {
                let reflected = self.taint(value).is_some() || re!(r"(?i)origin").is_match(value_text);
                if reflected && !re!(r#"^['"`]"#).is_match(value_text.trim()) {
                    let credentials = re!(r#"(?i)['"]Access-Control-Allow-Credentials['"]\s*,\s*(true|['"]true['"])"#).is_match(self.file_text);
                    self.finding(
                        "SEC-CORS",
                        c.span,
                        format!(
                            "The request's Origin is reflected into Access-Control-Allow-Origin{}: any site can read the responses.",
                            if credentials { " with Access-Control-Allow-Credentials: true" } else { "" }
                        ),
                        if credentials { Confidence::High } else { Confidence::Medium },
                        Self::pattern(crate::text::collapse(self.src.slice(c.span), 80)),
                        if credentials { Some(Severity::High) } else { None },
                    );
                }
            } else if !name.starts_with("access-control-")
                && name != "content-type"
                && let Some(t) = self.taint(value)
            {
                let ev = self.flow(&t, &format!("the {name} response header"));
                self.finding(
                    "SEC-HEADER-INJECTION",
                    c.span,
                    format!(
                        "Request data sets the `{name}` response header. Node rejects raw CR/LF in header values, but the client still controls the header (cookie injection, cache poisoning, redirects)."
                    ),
                    Confidence::Medium,
                    ev,
                    None,
                );
            }
        }
        // In-application log stores (`loginLogs.push(...)`, `logStream.write(...)`, `fs.appendFile('app.log', ...)`).
        let log_store = re!(r"(^|\.)(logs?|\w*Logs?|\w*_logs?|\w*Log(Stream|File|Entries|Lines))\.(push|unshift|write)$").is_match(&callee)
            || re!(r"^(fs\.)?(appendFile|appendFileSync)$").is_match(&callee) && re!(r"(?i)log").is_match(&a0_text);
        if log_store {
            let data = if callee.contains("appendFile") { args.get(1).and_then(|a| self.taint(a)) } else { self.first_tainted(&c.arguments) };
            if let Some(t) = data {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding(
                    "SEC-LOG-INJECTION",
                    c.span,
                    format!("Request data is appended to a log by {callee}() without neutralising line breaks: a value containing \\n forges log entries."),
                    Confidence::High,
                    ev,
                    None,
                );
            }
        }
        // Reflected XSS
        if let Some(a0) = a0 {
            let callee_text: String = self.src.slice(c.callee.span()).split_whitespace().collect();
            if re!(r"^(res|reply|response)(\.status\(\d+\))?\.(send|write|end)$").is_match(&callee_text)
                && (Self::dynamic_string(a0) || matches!(inner(a0), Expression::Identifier(_)))
                && let Some(t) = self.taint(a0)
                && (a0_text.contains('<') || Self::dynamic_string(a0))
            {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding("SEC-XSS", c.span, "Request data is written into an HTTP response body without encoding.".into(), Confidence::Medium, ev, None);
            }
        }
        // NoSQL injection
        if let Some(a0) = a0
            && matches!(
                method.as_str(),
                "find" | "findOne" | "findOneAndUpdate" | "updateOne" | "updateMany" | "deleteOne" | "deleteMany" | "countDocuments" | "where"
            )
        {
            let p = self.conv().raw_path(a0);
            if p.as_deref().is_some_and(|p| re!(r"^(req|request|ctx)\.(body|query)$").is_match(p)) {
                let pp = p.unwrap_or_default();
                self.finding(
                    "SEC-NOSQLI",
                    c.span,
                    format!("The raw request {pp} object is used as a query filter; operators like {{\"$ne\": null}} pass through."),
                    Confidence::High,
                    Self::pattern(format!("{pp} used as filter")),
                    None,
                );
            } else if let Expression::ObjectExpression(o) = inner(a0) {
                let mongo = self.file_text.contains("mongoose") || self.file_text.contains("mongodb") || self.file_text.contains("Schema(");
                for prop in &o.properties {
                    let ObjectPropertyKind::ObjectProperty(op) = prop else {
                        continue;
                    };
                    let vp = self.conv().raw_path(&op.value);
                    if mongo
                        && vp.as_deref().is_some_and(|v| re!(r"^(req|request)\.(body|query)\.\w+$").is_match(v))
                        && let Some(t) = self.taint(&op.value)
                    {
                        let ev = self.flow(&t, &format!("{callee}()"));
                        self.finding(
                            "SEC-NOSQLI",
                            c.span,
                            format!(
                                "Request field {} is used directly as a MongoDB filter value; an object value injects query operators.",
                                vp.unwrap_or_default()
                            ),
                            Confidence::Medium,
                            ev,
                            None,
                        );
                    }
                }
            }
        }
        // Mass assignment
        if matches!(
            method.as_str(),
            "create" | "insert" | "insertOne" | "build" | "update" | "updateOne" | "save" | "upsert" | "findByIdAndUpdate" | "findOneAndUpdate"
        ) || callee == "Object.assign"
        {
            for a in &args {
                let whole = self.conv().raw_path(a).is_some_and(|p| matches!(p.as_str(), "req.body" | "request.body" | "ctx.request.body"));
                let spread = matches!(inner(a), Expression::ObjectExpression(o) if o.properties.iter().any(|p| matches!(p, ObjectPropertyKind::SpreadProperty(sp) if self.conv().raw_path(&sp.argument).is_some_and(|x| x == "req.body" || x == "request.body"))));
                if whole || spread {
                    self.finding(
                        "SEC-MASS-ASSIGN",
                        c.span,
                        format!("The whole request body is passed to {callee}(); clients can set any field (e.g. role, ownerId, balance)."),
                        Confidence::Medium,
                        Self::pattern("request body passed wholesale"),
                        None,
                    );
                    break;
                }
            }
        }
        // Prototype pollution
        if args.len() >= 2
            && (re!(r"^(_|lodash)\.(merge|mergeWith|defaultsDeep|set|setWith)$").is_match(&callee)
                || matches!(callee.as_str(), "merge" | "deepmerge" | "deepMerge" | "extend"))
            && let Some(t) = c.arguments.iter().skip(1).filter_map(|a| a.as_expression()).find_map(|a| self.taint(a))
        {
            let ev = self.flow(&t, &format!("{callee}()"));
            self.finding("SEC-PROTO-POLLUTION", c.span, format!("Request data is deep-merged by {callee}()."), Confidence::Medium, ev, None);
        }
        // Unsafe deserialization
        if let Some(a0) = a0
            && callee.ends_with("unserialize")
        {
            if let Some(t) = self.taint(a0) {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding(
                    "SEC-DESERIALIZE",
                    c.span,
                    format!("Untrusted data is deserialised by {callee}(), which executes embedded functions."),
                    Confidence::High,
                    ev,
                    None,
                );
            } else {
                self.finding(
                    "SEC-DESERIALIZE",
                    c.span,
                    format!("{callee}() executes functions embedded in its input."),
                    Confidence::Medium,
                    Self::pattern("node-serialize unserialize"),
                    Some(Severity::Medium),
                );
            }
        }
        // JWT
        let jwt = re!(r"^(jwt|jsonwebtoken|JWT)\.(decode|verify|sign)$").captures(&callee).and_then(|cap| cap.get(2).map(|m| m.as_str().to_owned()));
        match jwt.as_deref() {
            Some("decode") if !re!(r"\b(jwt|jsonwebtoken|JWT)\.verify\s*\(").is_match(self.file_text) => {
                self.finding(
                    "SEC-JWT-DECODE",
                    c.span,
                    "jwt.decode() returns claims without checking the signature, and this module never calls jwt.verify().".into(),
                    Confidence::Medium,
                    Self::pattern("decode without verify in module"),
                    None,
                );
            }
            Some("verify") => {
                let opts = args.get(2).map(|x| self.arg_text(x)).unwrap_or_default();
                if re!(r#"(?i)algorithms\s*:\s*\[[^\]]*['"]none['"]"#).is_match(&opts) {
                    self.finding(
                        "SEC-JWT-ALG-NONE",
                        c.span,
                        "jwt.verify accepts the 'none' algorithm.".into(),
                        Confidence::High,
                        Self::pattern("algorithms includes none"),
                        None,
                    );
                }
                if re!(r"ignoreExpiration\s*:\s*true").is_match(&opts) {
                    self.finding(
                        "SEC-JWT-IGNORE-EXPIRATION",
                        c.span,
                        "jwt.verify is called with ignoreExpiration: true.".into(),
                        Confidence::High,
                        Self::pattern("ignoreExpiration: true"),
                        None,
                    );
                }
            }
            Some("sign") => {
                let all: String = args.iter().map(|x| self.arg_text(x)).collect::<Vec<_>>().join(" ");
                if !all.contains("expiresIn") && !re!(r"\bexp\s*:").is_match(&all) {
                    self.finding(
                        "SEC-JWT-NO-EXPIRY",
                        c.span,
                        "jwt.sign is called without expiresIn; the token never expires.".into(),
                        Confidence::Medium,
                        Self::pattern("no expiresIn"),
                        None,
                    );
                }
            }
            _ => {}
        }
        // Weak hashing of secrets
        if callee.ends_with("createHash")
            && let Some(Expression::StringLiteral(s)) = a0.map(inner)
            && matches!(s.value.as_str().to_ascii_lowercase().as_str(), "md5" | "sha1" | "md4")
        {
            let line = self.src.line_text(self.src.line_col(c.span.start).0);
            // Password context on the line, or a dedicated hashing helper (`export const hash = ...`).
            if re!(r"(?i)pass|pwd|secret|credential|\bpin\b|(const|let|function)\s+(hash|hashPassword|hashSecret|digestPassword)\b").is_match(line) {
                self.finding(
                    "SEC-WEAK-HASH",
                    c.span,
                    format!("{} is used to hash a password or secret.", s.value.as_str()),
                    Confidence::High,
                    Self::pattern(line.trim().to_owned()),
                    None,
                );
            }
        }
        if re!(r"(^|\.)create(De)?[cC]ipher$").is_match(&callee) {
            self.finding(
                "SEC-DEPRECATED-CIPHER",
                c.span,
                format!("{callee}() derives the key with MD5 and uses no IV."),
                Confidence::High,
                Self::pattern(callee.clone()),
                None,
            );
        }
        // CORS
        if callee == "cors"
            && let Some(a) = a0
        {
            let t = &self.arg_text(a);
            if re!(r"credentials\s*:\s*true").is_match(t) && re!(r#"origin\s*:\s*(['"`]\*['"`]|true)"#).is_match(t) {
                self.finding(
                    "SEC-CORS",
                    c.span,
                    "CORS allows credentials for any origin.".into(),
                    Confidence::High,
                    Self::pattern(crate::text::collapse(t, 80)),
                    None,
                );
            }
        }
        // vm with a sandbox carrying request data: the code string evaluates it.
        if re!(r"^(vm\.)?(runInContext|runInNewContext|runInThisContext|Script)$").is_match(&callee)
            && let Some(t) = args.get(1).and_then(|sb| self.taint(sb))
        {
            let ev = self.flow(&t, &format!("the sandbox of {callee}()"));
            self.finding(
                "SEC-CODE-INJECTION",
                c.span,
                format!("Request data is placed in the sandbox of {callee}() and evaluated by the code string; node:vm is not a security boundary."),
                Confidence::High,
                ev,
                None,
            );
        }
        // NoSQL injection through update/remove filters with request values (Mongo-style collections).
        if matches!(method.as_str(), "update" | "updateOne" | "updateMany" | "remove" | "deleteOne" | "deleteMany" | "findOneAndUpdate" | "replaceOne")
            && re!(r"(?i)collection|\bdb\.|mongo").is_match(&callee)
            && let Some(Expression::ObjectExpression(o)) = a0.map(inner)
        {
            for prop in &o.properties {
                let ObjectPropertyKind::ObjectProperty(op) = prop else {
                    continue;
                };
                // String()/Number() casts cannot carry an operator object.
                let cast = matches!(inner(&op.value), Expression::CallExpression(cc) if matches!(self.conv().callee(cc).as_str(), "String" | "Number" | "parseInt" | "parseFloat" | "Boolean"));
                if cast {
                    continue;
                }
                if let Some(t) = self.taint(&op.value) {
                    let ev = self.flow(&t, &format!("the filter of {callee}()"));
                    self.finding(
                        "SEC-NOSQLI",
                        c.span,
                        format!(
                            "Request data is used directly as a filter value in {callee}(); an object value (e.g. {{\"$ne\": -1}}) matches every document."
                        ),
                        Confidence::Medium,
                        ev,
                        None,
                    );
                    break;
                }
            }
        }
        // JWT verification without pinned algorithms (algorithm confusion).
        if re!(r"^(jwt|jsonwebtoken|JWT)\.verify$").is_match(&callee) || matches!(callee.as_str(), "expressJwt" | "jwtMiddleware" | "expressjwt") {
            let all: String = args.iter().map(|x| self.arg_text(x)).collect::<Vec<_>>().join(" ");
            if !all.contains("algorithms") {
                self.finding("SEC-JWT-ALG-UNPINNED", c.span, format!("{callee}() does not pin the accepted algorithms; tokens signed with an unexpected algorithm (e.g. HS256 with the public key) may be accepted."), Confidence::Medium, Scope::pattern("no algorithms option"), None);
            }
        }
        // XXE: libxmljs with external entities
        if re!(r"(?i)libxml|parseXml").is_match(&callee) && args.iter().any(|x| re!(r"(noent|dtdload|dtdvalid)\s*:\s*true").is_match(&self.arg_text(x))) {
            let tainted = args.first().and_then(|a| self.taint(a));
            let ev = match &tainted {
                Some(t) => self.flow(t, &format!("{callee}()")),
                None => Scope::pattern("noent: true"),
            };
            self.finding(
                "SEC-XXE",
                c.span,
                format!("{callee}() resolves external entities (noent/dtdload); a crafted XML document can read local files or reach internal hosts."),
                if tainted.is_some() { Confidence::High } else { Confidence::Medium },
                ev,
                None,
            );
        }
        // Template auto-escaping disabled
        if args.iter().any(|x| re!(r"autoescape\s*:\s*false|noEscape\s*:\s*true|escape\s*:\s*false").is_match(&self.arg_text(x)))
            && re!(r"(?i)setDefaults|configure|compile|Environment|engine|create").is_match(&callee)
        {
            self.finding(
                "SEC-TEMPLATE-AUTOESCAPE",
                c.span,
                format!("{callee}() disables HTML auto-escaping; every interpolated value becomes an XSS sink."),
                Confidence::High,
                Scope::pattern("autoescape disabled"),
                None,
            );
        }
        // Server-side template injection
        if TEMPLATE_ENGINE.is_match(&callee)
            && let Some(t) = a0.and_then(|a| self.taint(a))
        {
            let ev = self.flow(&t, &format!("{callee}()"));
            self.finding("SEC-SSTI", c.span, format!("Request data is compiled as a template by {callee}()."), Confidence::High, ev, None);
        }
        // Hard-coded session/cookie secrets
        if callee == "session" || callee == "cookieSession" || callee == "cookieParser" || callee == "expressSession" {
            let lit_secret = match a0.map(inner) {
                Some(Expression::StringLiteral(s)) if callee == "cookieParser" => Some(s.value.as_str().to_owned()),
                Some(Expression::ObjectExpression(o)) => o.properties.iter().find_map(|p| match p {
                    ObjectPropertyKind::ObjectProperty(op) if op.key.static_name().is_some_and(|k| k == "secret" || k == "keys") => match inner(&op.value) {
                        Expression::StringLiteral(s) => Some(s.value.as_str().to_owned()),
                        _ => None,
                    },
                    _ => None,
                }),
                _ => None,
            };
            if let Some(sec) = lit_secret.filter(|x| !x.is_empty()) {
                self.finding(
                    "SEC-HARDCODED-SESSION-SECRET",
                    c.span,
                    format!(
                        "The session signing secret is a string literal ({}); anyone with the source can forge sessions.",
                        proof_it_core::redact::redact_secret(&sec)
                    ),
                    Confidence::High,
                    Scope::pattern("literal secret"),
                    None,
                );
            }
            if callee != "cookieParser"
                && let Some(Expression::ObjectExpression(o)) = a0.map(inner)
            {
                let cookie = o.properties.iter().find_map(|p| match p {
                    ObjectPropertyKind::ObjectProperty(op) if op.key.static_name().is_some_and(|k| k == "cookie") => Some(inner(&op.value)),
                    _ => None,
                });
                match cookie {
                    None => {
                        self.finding("SEC-SESSION-DEFAULTS", c.span, "Session middleware configured without cookie options: the cookie is sent over plain HTTP (secure defaults to false) and without SameSite.".into(), Confidence::Medium, Scope::pattern("no cookie options"), None);
                    }
                    // `cookie: { path: '/' }`: options given, but `secure` left at its default (false).
                    Some(Expression::ObjectExpression(co))
                        if !co
                            .properties
                            .iter()
                            .any(|p| matches!(p, ObjectPropertyKind::ObjectProperty(op) if op.key.static_name().is_some_and(|k| k == "secure"))) =>
                    {
                        self.finding(
                            "SEC-SESSION-DEFAULTS",
                            co.span,
                            "Session cookie options do not set `secure`: it defaults to false, so the session cookie is also sent over plain HTTP.".into(),
                            Confidence::Medium,
                            Scope::pattern("cookie options without secure"),
                            None,
                        );
                    }
                    _ => {}
                }
            }
        }
        // Unrestricted uploads: multer()/fileUpload() without filter or size limits.
        if matches!(callee.as_str(), "multer" | "fileUpload" | "expressFileUpload" | "formidable") {
            let cfg = args.first().map(|x| self.src.slice(x.span())).unwrap_or("");
            let has_filter = cfg.contains("fileFilter") || cfg.contains("filter");
            let has_limit = cfg.contains("limits") || cfg.contains("maxFileSize") || cfg.contains("fileSize");
            if !has_filter || !has_limit {
                let missing = match (has_filter, has_limit) {
                    (false, false) => "no file-type filter and no size limit",
                    (false, true) => "no file-type filter",
                    _ => "no size limit",
                };
                self.finding(
                    "SEC-UNRESTRICTED-UPLOAD",
                    c.span,
                    format!("{callee}() is configured with {missing}: any file type and size is accepted."),
                    Confidence::Medium,
                    Scope::pattern(missing.to_owned()),
                    None,
                );
            }
        }
        // Error details sent to the client
        if re!(r"^(res|reply|response)(\.status\(\d+\))?\.(send|json|end|write)$").is_match(&callee.replace(' ', ""))
            && let Some(a) = a0
        {
            let t = self.src.slice(a.span());
            if re!(r"^(err|error|e|ex|exception)(\.stack)?$").is_match(t.trim()) || t.contains(".stack") {
                self.finding(
                    "SEC-ERROR-DISCLOSURE",
                    c.span,
                    format!("`{}` is sent to the client; stack traces and driver errors reveal internals.", crate::text::collapse(t, 40)),
                    Confidence::Medium,
                    Scope::pattern("error object in response"),
                    if t.contains(".stack") { Some(Severity::Medium) } else { None },
                );
            }
        }
        // Log injection
        // Structured loggers encode fields (logger.info('msg', { user })): only the message text matters.
        // console.* writes plain text: every argument matters.
        let console_log = re!(r"^console\.(log|info|warn|error|debug)$").is_match(&callee);
        let structured_log = re!(r"^(logger|log|winston|pino|this\.logger)\.(info|warn|error|debug|log|fatal|trace)$").is_match(&callee);
        if console_log || structured_log {
            let tainted = if console_log {
                self.first_tainted(&c.arguments)
            } else {
                a0.filter(|m| !matches!(inner(m), Expression::ObjectExpression(_))).and_then(|m| self.taint(m))
            };
            if let Some(t) = tainted {
                let ev = self.flow(&t, &format!("{callee}()"));
                self.finding(
                    "SEC-LOG-INJECTION",
                    c.span,
                    format!("Request data is written to logs by {callee}() without neutralising line breaks."),
                    Confidence::Medium,
                    ev,
                    None,
                );
            }
        }
        // Cookies
        if (callee == "session" || callee.ends_with(".cookie"))
            && args.iter().any(|x| re!(r"httpOnly\s*:\s*false|secure\s*:\s*false").is_match(self.src.slice(x.span())))
        {
            self.finding(
                "SEC-COOKIE-FLAGS",
                c.span,
                "Cookie is set with httpOnly: false or secure: false.".into(),
                Confidence::Medium,
                Self::pattern("cookie flags"),
                None,
            );
        }
    }
}

struct Collect<'q, 'c, 's> {
    scope: &'q mut Scope<'c, 's>,
    phase: u8, // 0 = taint fixpoint, 1 = sinks
    changed: bool,
    var_name: Option<String>,
}

impl<'a> Visit<'a> for Collect<'_, '_, '_> {
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, a: &ArrowFunctionExpression<'a>) {
        if self.phase == 0 {
            let before = self.scope.tainted.len();
            taint_request_params(self.scope, &a.params);
            if self.scope.tainted.len() != before {
                self.changed = true;
            }
        }
        walk::walk_arrow_function_expression(self, a);
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(init) = &d.init {
            if self.phase == 0 {
                if re!(r"^\s*(entry|header|zipEntry)\.(path|fileName|entryName|name)\b").is_match(self.scope.src.slice(init.span())) {
                    self.scope.entry_paths.extend(binding_names(&d.id));
                }
                if Scope::dynamic_string(init) {
                    self.scope.dynamic_strings.extend(binding_names(&d.id));
                }
                if CLIENT_IP_HEADER.is_match(self.scope.src.slice(init.span())) {
                    self.scope.spoofable_ips.extend(binding_names(&d.id));
                }
                if self.scope.is_request_object(init) {
                    self.scope.request_objects.extend(binding_names(&d.id));
                }
                if let Some(t) = self.scope.taint(init) {
                    for n in binding_names(&d.id) {
                        if let std::collections::hash_map::Entry::Vacant(e) = self.scope.tainted.entry(n) {
                            e.insert(t.clone());
                            self.changed = true;
                        }
                    }
                }
            }
            let saved = self.var_name.take();
            self.var_name = d.id.get_identifier_name().map(|n| n.as_str().to_owned());
            walk::walk_variable_declarator(self, d);
            self.var_name = saved;
            return;
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        // `q = "..." + x` / `q += ` + "`... ${x}`" + `: q now holds a dynamically built string.
        if self.phase == 0
            && matches!(a.operator, AssignmentOperator::Assign | AssignmentOperator::Addition)
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left
            && (Scope::dynamic_string(&a.right) || a.operator == AssignmentOperator::Addition && lit_str(&a.right).is_none())
            && self.scope.dynamic_strings.insert(id.name.as_str().to_owned())
        {
            self.changed = true;
        }
        if self.phase == 0
            // `q = x` and `q += x` (strings built in steps), `q ||= x`, `q ??= x`.
            && matches!(a.operator, AssignmentOperator::Assign | AssignmentOperator::Addition | AssignmentOperator::LogicalOr | AssignmentOperator::LogicalNullish)
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left
            && let Some(t) = self.scope.taint(&a.right)
            && !self.scope.tainted.contains_key(id.name.as_str())
        {
            self.scope.tainted.insert(id.name.as_str().to_owned(), t);
            self.changed = true;
        }
        if self.phase == 1 {
            let lhs = self.scope.src.slice(a.left.span()).to_owned();
            if lhs.contains("NODE_TLS_REJECT_UNAUTHORIZED") && re!(r#"['"`]0['"`]"#).is_match(self.scope.src.slice(a.right.span())) {
                self.scope.finding(
                    "SEC-TLS-DISABLED",
                    a.span,
                    "NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate validation process-wide.".into(),
                    Confidence::High,
                    Scope::pattern("NODE_TLS_REJECT_UNAUTHORIZED"),
                    None,
                );
            }
            if let Some(m) = a.left.as_member_expression()
                && m.static_property_name().is_some_and(|n| n == "innerHTML" || n == "outerHTML")
                && Scope::dynamic_string(&a.right)
            {
                self.scope.finding(
                    "SEC-XSS",
                    a.span,
                    "Dynamic HTML assigned to innerHTML/outerHTML.".into(),
                    Confidence::Low,
                    Scope::pattern("innerHTML"),
                    Some(Severity::Medium),
                );
            }
        }
        walk::walk_assignment_expression(self, a);
    }

    fn visit_call_expression(&mut self, c: &CallExpression<'a>) {
        if self.phase == 1 {
            let callee = self.scope.conv().callee(c);
            // Zip slip: write paths built from archive entry names.
            if re!(r"(createWriteStream|writeFile|writeFileSync|outputFile|mkdirSync)$").is_match(&callee)
                && let Some(a0) = c.arguments.first().and_then(|a| a.as_expression())
            {
                let t = self.scope.src.slice(a0.span());
                let entry_vars: Vec<&String> = self.scope.entry_paths.iter().collect();
                if re!(r"\b(entry|header|file|zipEntry)\.(path|fileName|entryName|name)\b").is_match(t)
                    || entry_vars.iter().any(|v| Regex::new(&format!(r"\b{}\b", regex::escape(v))).map(|r| r.is_match(t)).unwrap_or(false))
                {
                    self.scope.finding(
                        "SEC-ZIP-SLIP",
                        c.span,
                        format!("{callee}() writes to a path built from an archive entry name; entries like ../../app.js escape the target directory."),
                        Confidence::Medium,
                        Scope::pattern(crate::text::collapse(t, 60)),
                        None,
                    );
                }
            }
            // Angular: bypassSecurityTrust* with a non-literal value.
            if re!(r"bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)$").is_match(&callee)
                && c.arguments.first().and_then(|a| a.as_expression()).is_some_and(|a| !matches!(inner(a), Expression::StringLiteral(_)))
            {
                self.scope.finding(
                    "SEC-XSS",
                    c.span,
                    format!("{callee}() disables Angular's sanitisation for a dynamic value."),
                    Confidence::Medium,
                    Scope::pattern(callee.clone()),
                    Some(Severity::Medium),
                );
            }
            if self.scope.conv().callee(c) == "Math.random"
                && let Some(n) = self.var_name.clone().filter(|n| SECRET_NAME.is_match(n))
            {
                self.scope.finding(
                    "SEC-INSECURE-RANDOM",
                    c.span,
                    format!("Math.random() generates `{n}`, which looks security-sensitive."),
                    Confidence::Medium,
                    Scope::pattern(n.clone()),
                    None,
                );
            }
            self.scope.call(c);
        }
        walk::walk_call_expression(self, c);
    }

    fn visit_static_member_expression(&mut self, m: &StaticMemberExpression<'a>) {
        // libxml2 option flags enabling entity substitution / external DTDs (libxml2-wasm, libxmljs2, …).
        if self.phase == 1 && matches!(m.property.name.as_str(), "XML_PARSE_NOENT" | "XML_PARSE_DTDLOAD") {
            self.scope.finding(
                "SEC-XXE",
                m.span,
                format!("{} enables external entity / DTD loading when parsing XML.", m.property.name.as_str()),
                Confidence::Medium,
                Scope::pattern(m.property.name.as_str().to_owned()),
                None,
            );
        }
        walk::walk_static_member_expression(self, m);
    }

    fn visit_string_literal(&mut self, l: &StringLiteral<'a>) {
        // Code strings (vm / eval) that parse XML with external entities.
        if self.phase == 1 && l.value.contains("parseXml") && re!(r"noent\s*:\s*true").is_match(l.value.as_str()) {
            self.scope.finding(
                "SEC-XXE",
                l.span,
                "XML parsing with external entities (noent: true) inside an evaluated code string.".into(),
                Confidence::Medium,
                Scope::pattern("noent: true"),
                None,
            );
        }
    }

    fn visit_reg_exp_literal(&mut self, r: &RegExpLiteral<'a>) {
        if self.phase == 1 {
            let raw = self.scope.src.slice(r.span);
            let pattern = raw.rsplit_once('/').map_or(raw, |(p, _)| p).trim_start_matches('/');
            if NESTED_QUANTIFIER.is_match(pattern) {
                self.scope.finding(
                    "SEC-REDOS",
                    r.span,
                    format!("`/{pattern}/` nests a quantifier inside a quantified group; matching crafted input takes exponential time."),
                    Confidence::Medium,
                    Scope::pattern(pattern.to_owned()),
                    None,
                );
            }
        }
    }

    fn visit_jsx_attribute(&mut self, a: &JSXAttribute<'a>) {
        if self.phase == 1 && self.scope.src.slice(a.name.span()) == "dangerouslySetInnerHTML" {
            let v = a.value.as_ref().map(|x| self.scope.src.slice(x.span())).unwrap_or("");
            if !re!(r"(?i)sanitize|purify|escape").is_match(v) {
                self.scope.finding(
                    "SEC-XSS",
                    a.span,
                    "dangerouslySetInnerHTML with a value that is not visibly sanitised.".into(),
                    Confidence::Low,
                    Scope::pattern("dangerouslySetInnerHTML"),
                    Some(Severity::Medium),
                );
            }
        }
        walk::walk_jsx_attribute(self, a);
    }

    fn visit_new_expression(&mut self, n: &NewExpression<'a>) {
        if self.phase == 1
            && matches!(&n.callee, Expression::Identifier(id) if id.name.as_str() == "RegExp")
            && let Some(t) = n.arguments.first().and_then(|a| a.as_expression()).and_then(|a| self.scope.taint(a))
        {
            let ev = self.scope.flow(&t, "new RegExp()");
            self.scope.finding(
                "SEC-REGEX-INJECTION",
                n.span,
                "Request data is compiled into a regular expression (ReDoS / unintended matching).".into(),
                Confidence::High,
                ev,
                None,
            );
        }
        if self.phase == 1 && matches!(&n.callee, Expression::Identifier(id) if id.name.as_str() == "Function") && !n.arguments.is_empty() {
            match self.scope.first_tainted(&n.arguments) {
                Some(t) => {
                    let ev = self.scope.flow(&t, "new Function()");
                    self.scope.finding("SEC-CODE-INJECTION", n.span, "Request data is compiled by new Function().".into(), Confidence::High, ev, None);
                }
                None => self.scope.finding(
                    "SEC-EVAL",
                    n.span,
                    "Dynamic code compilation with new Function().".into(),
                    Confidence::Low,
                    Scope::pattern("new Function"),
                    Some(Severity::Low),
                ),
            }
        }
        walk::walk_new_expression(self, n);
    }

    fn visit_template_literal(&mut self, t: &TemplateLiteral<'a>) {
        if self.phase == 1 && !t.expressions.is_empty() {
            let quasis: String = t.quasis.iter().map(|q| q.value.raw.as_str()).collect::<Vec<_>>().join("${}");
            let xml_tags = re!(r"<[A-Za-z][\w:.-]*(\s[^<>]*)?>\$\{\}</[A-Za-z][\w:.-]*>").is_match(&quasis);
            let html = re!(r"(?i)<(html|body|div|span|p|a|script|table|td|li|h[1-6]|br|img|form|input)[\s>/]").is_match(&quasis);
            let xml_context =
                re!(r"(?i)<\?xml|xmlns|soap(env)?:").is_match(&quasis) || re!(r#"(?i)['"](application|text)/(soap\+)?xml['"]"#).is_match(self.scope.file_text);
            if xml_tags
                && !html
                && xml_context
                && let Some(tt) = t.expressions.iter().find_map(|x| self.scope.taint(x))
            {
                let ev = self.scope.flow(&tt, "an XML document built by string interpolation");
                self.scope.finding(
                    "SEC-XML-INJECTION",
                    t.span,
                    "Request data is interpolated into XML without escaping: a value like `x</name><role>admin</role><name>` adds elements the consumer trusts.".into(),
                    Confidence::High,
                    ev,
                    None,
                );
            }
        }
        walk::walk_template_literal(self, t);
    }

    fn visit_object_property(&mut self, p: &ObjectProperty<'a>) {
        if self.phase == 1 && p.key.static_name().is_some_and(|k| k == "keyGenerator") && CLIENT_IP_HEADER.is_match(self.scope.src.slice(p.value.span())) {
            self.scope.finding(
                "SEC-SPOOFABLE-CLIENT-IP",
                p.span,
                "The rate limiter's keyGenerator uses a client-supplied IP header: rotating X-Forwarded-For bypasses the limit.".into(),
                Confidence::High,
                Scope::pattern("keyGenerator reads an IP header"),
                None,
            );
        }
        if self.phase == 1
            && p.key.static_name().is_some_and(|k| k == "introspection")
            && matches!(inner(&p.value), Expression::BooleanLiteral(b) if b.value)
            && re!(r"(?i)graphql|apollo").is_match(self.scope.file_text)
        {
            self.scope.finding(
                "SEC-GRAPHQL-INTROSPECTION",
                p.span,
                "GraphQL introspection is enabled unconditionally: anyone can download the full schema, including hidden queries and mutations.".into(),
                Confidence::High,
                Scope::pattern("introspection: true"),
                None,
            );
        }
        if self.phase == 1 && p.key.static_name().is_some_and(|k| k == "$where") && (Scope::dynamic_string(&p.value) || self.scope.taint(&p.value).is_some()) {
            let ev = match self.scope.taint(&p.value) {
                Some(t) => self.scope.flow(&t, "a MongoDB $where clause"),
                None => Scope::pattern("dynamic $where"),
            };
            self.scope.finding(
                "SEC-NOSQLI",
                p.span,
                "A MongoDB $where clause is built from runtime values: it is JavaScript evaluated by the database (server-side JS injection).".into(),
                Confidence::High,
                ev,
                Some(Severity::Critical),
            );
        }
        if self.phase == 1 && p.key.static_name().is_some_and(|k| k == "rejectUnauthorized") && matches!(&p.value, Expression::BooleanLiteral(b) if !b.value) {
            self.scope.finding(
                "SEC-TLS-DISABLED",
                p.span,
                "rejectUnauthorized: false disables certificate validation.".into(),
                Confidence::High,
                Scope::pattern("rejectUnauthorized: false"),
                None,
            );
        }
        walk::walk_object_property(self, p);
    }

    fn visit_binary_expression(&mut self, b: &BinaryExpression<'a>) {
        if self.phase == 1 && matches!(b.operator, BinaryOperator::StrictEquality | BinaryOperator::StrictInequality) {
            let (l, r) = (self.scope.src.slice(b.left.span()).to_owned(), self.scope.src.slice(b.right.span()).to_owned());
            let trivial = |s: &str| {
                matches!(s.trim(), "null" | "undefined" | "''" | "\"\"" | "``")
                    || s.trim().parse::<f64>().is_ok()
                    || s.contains("typeof")
                    || s.ends_with(".length")
            };
            let handler_file = self.scope.file_text.contains("req") || self.scope.file_text.contains("ctx");
            if handler_file && (SECRET_CMP.is_match(&l) || SECRET_CMP.is_match(&r)) && !trivial(&l) && !trivial(&r) {
                self.scope.finding(
                    "SEC-TIMING-COMPARE",
                    b.span,
                    format!("Secret-like values compared with {} (early-exit comparison).", b.operator.as_str()),
                    Confidence::Low,
                    Scope::pattern(crate::text::collapse(self.scope.src.slice(b.span), 80)),
                    None,
                );
            }
        }
        walk::walk_binary_expression(self, b);
    }
}

fn analyze_scope<'s>(
    src: &Source<'s>,
    stmts: &[Statement<'_>],
    params: Option<&FormalParameters<'_>>,
    seeds: &[(String, Taint)],
    objects: &HashMap<String, String>,
    passthrough: &BTreeSet<String>,
) -> (Vec<Finding>, Vec<(String, usize, Taint)>) {
    let aliases = crate::expr::collect_aliases(src, stmts);
    let mut scope = Scope {
        src,
        aliases,
        tainted: HashMap::new(),
        dynamic_strings: BTreeSet::new(),
        tainted_calls: vec![],
        entry_paths: BTreeSet::new(),
        request_objects: BTreeSet::new(),
        spoofable_ips: BTreeSet::new(),
        objects,
        passthrough,
        file_text: src.text,
        out: vec![],
    };
    for (n, t) in seeds {
        scope.tainted.insert(n.clone(), t.clone());
    }
    // NestJS: parameters decorated with @Body/@Query/@Param/@Headers are sources.
    if let Some(ps) = params {
        for p in &ps.items {
            if p.decorators.iter().any(|d| re!(r"^(Body|Query|Param|Headers)\b").is_match(src.slice(d.expression.span()))) {
                for n in binding_names(&p.pattern) {
                    scope.tainted.insert(n.clone(), Taint { source: format!("@decorated parameter {n}"), line: src.line_col(p.span.start).0 });
                }
            }
        }
    }
    // Seed parameters before the fixpoint so locals derived from them are tainted too.
    if let Some(ps) = params {
        taint_request_params(&mut scope, ps);
    }
    for _ in 0..5 {
        let mut c = Collect { scope: &mut scope, phase: 0, changed: false, var_name: None };
        for s in stmts {
            c.visit_statement(s);
        }
        if !c.changed {
            break;
        }
    }
    let mut c = Collect { scope: &mut scope, phase: 1, changed: false, var_name: None };
    for s in stmts {
        c.visit_statement(s);
    }
    (scope.out, scope.tainted_calls)
}

/// `({ query, params }: Request, res) => …`: destructured request properties are sources.
fn taint_request_params(scope: &mut Scope<'_, '_>, ps: &FormalParameters<'_>) {
    let name = |i: usize| ps.items.get(i).and_then(|p| p.pattern.get_identifier_name()).map(|n| n.as_str().to_owned()).unwrap_or_default();
    let seed = |scope: &mut Scope<'_, '_>, i: usize, what: &str| {
        if let Some(p) = ps.items.get(i) {
            for n in binding_names(&p.pattern) {
                scope.tainted.insert(n, Taint { source: format!("{what} (client-controlled)"), line: scope.src.line_col(p.span.start).0 });
            }
        }
    };
    // GraphQL resolvers `(parent, args, context, info)`: `args` comes from the query.
    if ps.items.len() >= 2
        && re!(r"(?i)graphql|apollo|\bresolvers?\b|typeDefs").is_match(scope.file_text)
        && (matches!(name(1).as_str(), "args" | "_args" | "input" | "variables")
            || matches!(ps.items.get(1).map(|p| &p.pattern), Some(BindingPattern::ObjectPattern(_)))
                && matches!(name(0).as_str(), "parent" | "_parent" | "root" | "_root" | "_" | "obj" | "source"))
    {
        seed(scope, 1, "GraphQL resolver argument");
    }
    // RPC method handlers `(params, callback)` / `(err, params, callback)` (XML-RPC, JSON-RPC).
    if re!(r"(?i)xml-?rpc|jayson|json-?rpc").is_match(scope.file_text)
        && ps.items.len() >= 2
        && matches!(name(ps.items.len() - 1).as_str(), "callback" | "cb" | "done" | "reply" | "respond")
        && let Some(i) = (0..ps.items.len() - 1).find(|&i| matches!(name(i).as_str(), "params" | "args" | "parameters"))
    {
        seed(scope, i, "RPC method parameter");
    }
    let looks_like_handler = ps.items.len() >= 2
        && ps.items.get(1).and_then(|p| p.pattern.get_identifier_name()).is_some_and(|n| matches!(n.as_str(), "res" | "response" | "reply" | "_res"))
        || ps.items.first().and_then(|p| p.type_annotation.as_ref()).is_some_and(|t| scope.src.slice(t.span()).contains("Request"));
    if !looks_like_handler {
        return;
    }
    if let Some(BindingPattern::ObjectPattern(op)) = ps.items.first().map(|p| &p.pattern) {
        for prop in &op.properties {
            let key = prop.key.static_name().map(|k| k.into_owned()).unwrap_or_default();
            if matches!(key.as_str(), "body" | "query" | "params" | "headers" | "cookies" | "files" | "file" | "url" | "originalUrl" | "path") {
                for n in binding_names(&prop.value) {
                    scope.tainted.insert(n, Taint { source: format!("req.{key} (destructured)"), line: scope.src.line_col(prop.span.start).0 });
                }
            }
        }
    }
}

/// Functions declared in this file (`function f(x) {...}`, `const f = (x) => ...`)
/// whose return value is tainted when their parameters are: calls to them
/// propagate taint. Judged from the body, so a "sanitizer" that returns its
/// input unchanged does not clear taint.
fn passthrough_functions(program: &Program<'_>, src: &Source<'_>, objects: &HashMap<String, String>) -> BTreeSet<String> {
    struct Returns<'x, 'a> {
        out: Vec<&'x Expression<'a>>,
    }
    impl<'x, 'a> Returns<'x, 'a> {
        fn stmts(&mut self, ss: &'x [Statement<'a>]) {
            for s in ss {
                self.stmt(s);
            }
        }
        fn stmt(&mut self, s: &'x Statement<'a>) {
            match s {
                Statement::ReturnStatement(r) => self.out.extend(r.argument.as_ref()),
                Statement::BlockStatement(b) => self.stmts(&b.body),
                Statement::IfStatement(i) => {
                    self.stmt(&i.consequent);
                    if let Some(a) = &i.alternate {
                        self.stmt(a);
                    }
                }
                Statement::TryStatement(t) => {
                    self.stmts(&t.block.body);
                    if let Some(h) = &t.handler {
                        self.stmts(&h.body.body);
                    }
                }
                Statement::SwitchStatement(sw) => {
                    for c in &sw.cases {
                        self.stmts(&c.consequent);
                    }
                }
                _ => {}
            }
        }
    }
    /// A function found in the file: name, parameters, and a block or expression body.
    struct LocalFn<'x, 'a>(String, &'x FormalParameters<'a>, Option<&'x [Statement<'a>]>, Option<&'x Expression<'a>>);
    struct Fns<'x, 'a> {
        found: Vec<LocalFn<'x, 'a>>,
    }
    impl<'x, 'a> Fns<'x, 'a> {
        fn stmt(&mut self, s: &'x Statement<'a>) {
            match s {
                Statement::FunctionDeclaration(f) => {
                    if let (Some(id), Some(b)) = (&f.id, &f.body) {
                        self.found.push(LocalFn(id.name.as_str().to_owned(), &f.params, Some(&b.statements), None));
                    }
                }
                Statement::VariableDeclaration(v) => {
                    for d in &v.declarations {
                        let (Some(n), Some(init)) = (d.id.get_identifier_name(), d.init.as_ref()) else { continue };
                        match inner(init) {
                            Expression::ArrowFunctionExpression(a) => match (&a.body, a.body.as_expression()) {
                                (_, Some(e)) => self.found.push(LocalFn(n.as_str().to_owned(), &a.params, None, Some(e))),
                                (ArrowFunctionBody::FunctionBody(b), None) => {
                                    self.found.push(LocalFn(n.as_str().to_owned(), &a.params, Some(&b.statements), None))
                                }
                                _ => {}
                            },
                            Expression::FunctionExpression(f) => {
                                if let Some(b) = &f.body {
                                    self.found.push(LocalFn(n.as_str().to_owned(), &f.params, Some(&b.statements), None));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Statement::ExportDeclaration(e) => {
                    if let Declaration::FunctionDeclaration(f) = &e.declaration
                        && let (Some(id), Some(b)) = (&f.id, &f.body)
                    {
                        self.found.push(LocalFn(id.name.as_str().to_owned(), &f.params, Some(&b.statements), None));
                    }
                }
                _ => {}
            }
        }
    }
    let mut fns = Fns { found: vec![] };
    for s in &program.body {
        fns.stmt(s);
    }
    let none = BTreeSet::new();
    let mut out = BTreeSet::new();
    for LocalFn(name, params, body, expr) in fns.found {
        let names: Vec<String> = params.items.iter().flat_map(|p| binding_names(&p.pattern)).collect();
        if names.is_empty() {
            continue;
        }
        let stmts: &[Statement<'_>] = body.unwrap_or(&[]);
        let aliases = crate::expr::collect_aliases(src, stmts);
        let mut scope = Scope {
            src,
            aliases,
            tainted: names.iter().map(|n| (n.clone(), Taint { source: format!("argument of {name}"), line: 0 })).collect(),
            dynamic_strings: BTreeSet::new(),
            tainted_calls: vec![],
            entry_paths: BTreeSet::new(),
            request_objects: BTreeSet::new(),
            spoofable_ips: BTreeSet::new(),
            objects,
            passthrough: &none,
            file_text: src.text,
            out: vec![],
        };
        for _ in 0..5 {
            let mut c = Collect { scope: &mut scope, phase: 0, changed: false, var_name: None };
            for s in stmts {
                c.visit_statement(s);
            }
            if !c.changed {
                break;
            }
        }
        let mut r = Returns { out: vec![] };
        r.stmts(stmts);
        r.out.extend(expr);
        // A function named like a sanitizer keeps that status only if its body
        // actually transforms or checks the value; one that hands it back does not.
        let body_text =
            body.map_or_else(|| expr.map_or("", |e| src.slice(e.span())).to_owned(), |b| b.iter().map(|s| src.slice(s.span())).collect::<Vec<_>>().join("\n"));
        let transforms =
            re!(r"(?i)\.replace(All)?\s*\(|encode|escape|sanitiz|purify|validator\.|\.test\s*\(|\.match\s*\(|parseInt|parseFloat|Number\s*\(|\bthrow\b")
                .is_match(&body_text);
        let tainted_return = r.out.iter().any(|e| scope.taint(e).is_some());
        if tainted_return && (!SANITIZER.is_match(&name) || !transforms) {
            out.insert(name);
        }
    }
    out
}

/// Every `name = { ... }` initialiser in the file (option objects passed by name).
fn object_literals(program: &Program<'_>, src: &Source<'_>) -> HashMap<String, String> {
    struct O<'c, 's> {
        src: &'c Source<'s>,
        out: HashMap<String, String>,
    }
    impl<'a> Visit<'a> for O<'_, '_> {
        fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
            if let (Some(n), Some(Expression::ObjectExpression(o))) = (d.id.get_identifier_name(), d.init.as_ref().map(inner)) {
                let e = self.out.entry(n.as_str().to_owned()).or_default();
                e.push(' ');
                e.push_str(self.src.slice(o.span));
            }
            walk::walk_variable_declarator(self, d);
        }
    }
    let mut o = O { src, out: HashMap::new() };
    o.visit_program(program);
    o.out
}

pub fn detect(program: &Program<'_>, src: &Source<'_>) -> Vec<Finding> {
    /// Analyses every function; with `seeds`, only named functions that receive tainted
    /// arguments somewhere in this module, with those parameters tainted.
    struct F<'c, 's> {
        src: &'c Source<'s>,
        out: Vec<Finding>,
        calls: Vec<(String, usize, Taint)>,
        seeds: Option<&'c [(String, usize, Taint)]>,
        objects: &'c HashMap<String, String>,
        passthrough: &'c BTreeSet<String>,
    }
    impl<'a> Visit<'a> for F<'_, '_> {
        fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
            if let Some(b) = &f.body {
                match self.seeds {
                    None => {
                        let (fs, calls) = analyze_scope(self.src, &b.statements, Some(&f.params), &[], self.objects, self.passthrough);
                        self.out.extend(fs);
                        self.calls.extend(calls);
                    }
                    Some(seeds) => {
                        let name = f.id.as_ref().map(|i| i.name.as_str().to_owned()).unwrap_or_default();
                        let params: Vec<String> =
                            f.params.items.iter().map(|p| p.pattern.get_identifier_name().map_or_else(String::new, |n| n.as_str().to_owned())).collect();
                        let mine: Vec<(String, Taint)> = seeds
                            .iter()
                            .filter(|(c, i, _)| *c == name && *i < params.len() && !params[*i].is_empty())
                            .map(|(_, i, t)| (params[*i].clone(), Taint { source: format!("{} (via call to {name})", t.source), line: t.line }))
                            .collect();
                        if !mine.is_empty() {
                            let (fs, calls) = analyze_scope(self.src, &b.statements, Some(&f.params), &mine, self.objects, self.passthrough);
                            self.out.extend(fs);
                            self.calls.extend(calls);
                        }
                    }
                }
            }
            walk::walk_function(self, f, flags);
        }
    }
    let objects = object_literals(program, src);
    let passthrough = passthrough_functions(program, src, &objects);
    let (top, top_calls) = analyze_scope(src, &program.body, None, &[], &objects, &passthrough);
    let mut f = F { src, out: top, calls: top_calls, seeds: None, objects: &objects, passthrough: &passthrough };
    f.visit_program(program);
    // Interprocedural (same module, two levels): re-analyse local helpers called with tainted data.
    let mut pending = std::mem::take(&mut f.calls);
    for _ in 0..2 {
        if pending.is_empty() {
            break;
        }
        let mut g = F { src, out: vec![], calls: vec![], seeds: Some(&pending), objects: &objects, passthrough: &passthrough };
        g.visit_program(program);
        f.out.extend(g.out);
        pending = g.calls;
    }
    // Arrow bodies are analysed within their enclosing scope (taint flows into callbacks).
    let mut seen = BTreeSet::new();
    f.out.retain(|x| seen.insert((x.rule_id.clone(), x.location.as_ref().map(|l| l.line))));
    f.out
}
