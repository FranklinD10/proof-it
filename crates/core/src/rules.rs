//! The catalogue of built-in detector rules, shared by every language adapter so
//! a rule id means the same thing (title, severity, CWE, advice) in every language.

use crate::types::Severity;

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
