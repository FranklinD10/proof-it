//! Intra-procedural taint for Go.
//!
//! Sources are recognised from the *declared type* of handler parameters
//! (`*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`) and a few
//! well-known router helpers (`mux.Vars`, `chi.URLParam`). Taint flows through
//! assignments, string building, conversions, method calls on tainted values,
//! a fixed list of propagating library calls, and functions in the same file
//! whose return value carries a tainted argument (judged from their bodies).

use crate::{Src, descendants};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
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

/// Parameter names, in order (`a, b int` declares two).
pub fn param_names(src: &Src<'_>, params: Node<'_>) -> Vec<String> {
    param_types(src, params).into_iter().map(|(n, _)| n).collect()
}

/// (name, declared type) for every parameter.
pub fn param_types(src: &Src<'_>, params: Node<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut c = params.walk();
    for p in params.named_children(&mut c).filter(|p| p.kind() == "parameter_declaration" || p.kind() == "variadic_parameter_declaration") {
        let ty = p.child_by_field_name("type").map(|t| src.compact(t)).unwrap_or_default();
        let mut cc = p.walk();
        for n in p.children_by_field_name("name", &mut cc) {
            out.push((src.of(n).to_owned(), ty.clone()));
        }
    }
    out
}

/// What a function's parameters are.
#[derive(Default, Clone)]
pub struct Roles {
    /// `*http.Request` parameters (and `c.Request` of framework contexts).
    pub requests: Vec<String>,
    /// gin / echo / fiber context parameters.
    pub contexts: Vec<String>,
    /// `http.ResponseWriter` parameters.
    pub writers: Vec<String>,
}

impl Roles {
    pub fn of(src: &Src<'_>, params: Option<Node<'_>>) -> Self {
        let mut r = Roles::default();
        for (name, ty) in params.map(|p| param_types(src, p)).unwrap_or_default() {
            if re!(r"^\*?http\.Request$").is_match(&ty) {
                r.requests.push(name);
            } else if re!(r"^(\*?gin\.Context|echo\.Context|\*?fiber\.Ctx)$").is_match(&ty) {
                r.requests.push(format!("{name}.Request"));
                r.contexts.push(name);
            } else if ty == "http.ResponseWriter" {
                r.writers.push(name);
            }
        }
        r
    }
}

#[derive(Clone, Debug)]
pub struct Taint {
    pub source: String,
    pub line: usize,
}

pub struct Scope<'a, 's> {
    pub src: &'a Src<'s>,
    pub roles: Roles,
    pub tainted: HashMap<String, Taint>,
    /// Locals holding a string built from runtime values (`q := "…" + x`).
    pub dynamic: BTreeSet<String>,
    /// File functions that propagate taint from arguments to their result.
    pub passthrough: &'a BTreeSet<String>,
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

impl<'a, 's> Scope<'a, 's> {
    pub fn new(src: &'a Src<'s>, roles: Roles, passthrough: &'a BTreeSet<String>) -> Self {
        Scope { src, roles, tainted: HashMap::new(), dynamic: BTreeSet::new(), passthrough }
    }

    fn starts_with_request(&self, text: &str) -> bool {
        self.roles.requests.iter().any(|r| text.starts_with(&format!("{r}.")))
    }
    fn starts_with_context(&self, text: &str) -> bool {
        self.roles.contexts.iter().any(|c| text.starts_with(&format!("{c}.")))
    }

    /// Is this call a request source? Returns its description.
    fn source_call(&self, callee: &str, call: Node<'_>) -> Option<String> {
        let tail = |prefixes: &[String]| prefixes.iter().find_map(|p| callee.strip_prefix(&format!("{p}.")).map(str::to_owned));
        if let Some(m) = tail(&self.roles.requests)
            && re!(r"^(FormValue|PostFormValue|Cookie|Cookies|UserAgent|Referer|PathValue|URL\.Query\(\)\.Get|URL\.Query|Header\.Get|Header\.Values|Form\.Get|PostForm\.Get|URL\.EscapedPath)$").is_match(&m)
        {
            return Some(callee.to_owned());
        }
        if let Some(m) = tail(&self.roles.contexts)
            && re!(r"^(Param|Params|Query|DefaultQuery|QueryArray|QueryMap|GetQuery|PostForm|DefaultPostForm|PostFormArray|GetPostForm|GetHeader|QueryParam|QueryParams|FormValue|FormParams|Cookie|Body|GetRawData|FullPath|Path|OriginalURL|Hostname)$").is_match(&m)
        {
            return Some(callee.to_owned());
        }
        if re!(r"^(mux\.Vars|chi\.URLParam|chi\.URLParamFromCtx|httprouter\.ParamsFromContext)$").is_match(callee) {
            return Some(callee.to_owned());
        }
        // io.ReadAll(r.Body)
        if re!(r"^(io|ioutil)\.ReadAll$").is_match(callee)
            && let Some(a) = args(call).first()
            && self.starts_with_request(&self.src.compact(*a))
        {
            return Some(format!("{callee}({})", self.src.compact(*a)));
        }
        None
    }

    fn source_selector(&self, text: &str) -> bool {
        self.starts_with_request(text) && re!(r"\.(URL\.(Path|RawQuery|RawPath|Fragment|User)|Form|PostForm|Header|Body|Host|RequestURI|URL)$").is_match(text)
            || self.starts_with_context(text) && re!(r"\.(Params|Keys)$").is_match(text)
    }

    pub fn taint(&self, n: Node<'_>) -> Option<Taint> {
        let at = |source: String| Some(Taint { source, line: n.start_position().row + 1 });
        match n.kind() {
            "identifier" => self.tainted.get(self.src.of(n)).cloned(),
            "selector_expression" => {
                let t = self.src.compact(n);
                if self.source_selector(&t) {
                    return at(t);
                }
                n.child_by_field_name("operand").and_then(|o| self.taint(o))
            }
            "index_expression" | "slice_expression" => n.child_by_field_name("operand").and_then(|o| self.taint(o)),
            "parenthesized_expression" | "unary_expression" | "type_conversion_expression" | "type_assertion_expression" => {
                let mut c = n.walk();
                let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
                kids.into_iter().find_map(|k| self.taint(k))
            }
            "binary_expression" => {
                n.child_by_field_name("left").and_then(|l| self.taint(l)).or_else(|| n.child_by_field_name("right").and_then(|r| self.taint(r)))
            }
            "composite_literal" | "literal_value" | "keyed_element" | "literal_element" | "expression_list" => {
                let mut c = n.walk();
                let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
                kids.into_iter().find_map(|k| self.taint(k))
            }
            "call_expression" => self.call_taint(n),
            _ => None,
        }
    }

    fn call_taint(&self, call: Node<'_>) -> Option<Taint> {
        let f = call.child_by_field_name("function")?;
        let callee = self.src.compact(f);
        if let Some(s) = self.source_call(&callee, call) {
            return Some(Taint { source: s, line: call.start_position().row + 1 });
        }
        if is_sanitizer(&callee) {
            return None;
        }
        let any_arg = || args(call).into_iter().find_map(|a| self.taint(a));
        // []byte(x), string(x): parsed as calls when the type is a simple name.
        if matches!(callee.as_str(), "string" | "[]byte" | "[]rune") {
            return any_arg();
        }
        if is_propagator(&callee) || self.passthrough.contains(&callee) {
            return any_arg();
        }
        // Method call on a tainted value (`x.String()`, `values.Get("k")`).
        if f.kind() == "selector_expression"
            && let Some(t) = f.child_by_field_name("operand").and_then(|o| self.taint(o))
        {
            return Some(t);
        }
        None
    }

    /// A string assembled from non-constant parts.
    pub fn dynamic_string(&self, n: Node<'_>) -> bool {
        match n.kind() {
            "binary_expression" => {
                let op = n.child_by_field_name("operator").map(|o| self.src.of(o)).unwrap_or("");
                op == "+" && ["left", "right"].iter().any(|s| n.child_by_field_name(s).is_some_and(|x| !is_literal(x) || self.dynamic_string(x)))
            }
            "call_expression" => {
                let callee = n.child_by_field_name("function").map(|f| self.src.compact(f)).unwrap_or_default();
                re!(r"^fmt\.Sprint(f|ln)?$|^strings\.(Join|Replace|ReplaceAll|Repeat)$").is_match(&callee) && args(n).iter().skip(1).any(|a| !is_literal(*a))
            }
            "identifier" => self.dynamic.contains(self.src.of(n)),
            "parenthesized_expression" => n.named_child(0).is_some_and(|x| self.dynamic_string(x)),
            _ => false,
        }
    }

    /// Propagate taint through every assignment in `body` (to a fixpoint).
    pub fn propagate(&mut self, body: Node<'_>) {
        let assigns: Vec<Node<'_>> = ["short_var_declaration", "assignment_statement", "var_spec", "range_clause", "call_expression"]
            .iter()
            .flat_map(|k| descendants(body, k))
            .collect();
        for _ in 0..4 {
            let before = (self.tainted.len(), self.dynamic.len());
            for a in &assigns {
                self.assign(*a);
            }
            if (self.tainted.len(), self.dynamic.len()) == before {
                break;
            }
        }
    }

    fn mark(&mut self, name: &str, t: Option<Taint>, dynamic: bool) {
        if name == "_" || !is_ident(name) {
            return;
        }
        if let Some(t) = t {
            self.tainted.entry(name.to_owned()).or_insert(t);
        }
        if dynamic {
            self.dynamic.insert(name.to_owned());
        }
    }

    fn assign(&mut self, n: Node<'_>) {
        match n.kind() {
            "short_var_declaration" | "assignment_statement" => {
                let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) else { return };
                let lefts = list(l);
                let rights = list(r);
                let op = n.child_by_field_name("operator").map(|o| self.src.of(o)).unwrap_or("=");
                for (i, lhs) in lefts.iter().enumerate() {
                    // `rows, err := db.Query(...)`: one right-hand side for several targets.
                    let rhs = if rights.len() == lefts.len() {
                        rights.get(i)
                    } else if i == 0 {
                        rights.first()
                    } else {
                        None
                    };
                    let Some(rhs) = rhs else { continue };
                    let t = self.taint(*rhs);
                    let dynamic = self.dynamic_string(*rhs) || (op == "+=" && !is_literal(*rhs));
                    self.mark(&self.src.compact(*lhs), t, dynamic);
                }
            }
            "var_spec" => {
                let Some(v) = n.child_by_field_name("value") else { return };
                let rights = list(v);
                let mut c = n.walk();
                let names: Vec<Node<'_>> = n.children_by_field_name("name", &mut c).collect();
                for (i, name) in names.iter().enumerate() {
                    if let Some(rhs) = rights.get(i).or(rights.first().filter(|_| i == 0)) {
                        let (t, d) = (self.taint(*rhs), self.dynamic_string(*rhs));
                        self.mark(self.src.of(*name), t, d);
                    }
                }
            }
            "range_clause" => {
                let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) else { return };
                if let Some(t) = self.taint(r) {
                    for lhs in list(l) {
                        self.mark(&self.src.compact(lhs), Some(t.clone()), false);
                    }
                }
            }
            "call_expression" => self.bind(n),
            _ => {}
        }
    }

    /// Calls that fill a variable with request data: `c.ShouldBindJSON(&in)`,
    /// `json.NewDecoder(r.Body).Decode(&in)`, `json.Unmarshal(body, &in)`.
    fn bind(&mut self, call: Node<'_>) {
        let Some(f) = call.child_by_field_name("function") else { return };
        let callee = self.src.compact(f);
        let a = args(call);
        let target = |n: Option<&Node<'_>>| n.map(|x| self.src.compact(*x).trim_start_matches('&').to_owned());
        let ctx_bind = self
            .roles
            .contexts
            .iter()
            .any(|c| callee.starts_with(&format!("{c}.")) && re!(r"\.(ShouldBind\w*|Bind\w*|BodyParser|QueryParser|ParamsParser)$").is_match(&callee));
        let decoder = re!(r"^json\.NewDecoder\((.+)\)\.Decode$").captures(&callee).is_some_and(|m| {
            let inner = m.get(1).map_or("", |x| x.as_str());
            self.starts_with_request(inner) || self.tainted.contains_key(inner)
        });
        let unmarshal = re!(r"^(json|xml|yaml)\.Unmarshal$").is_match(&callee) && a.first().is_some_and(|b| self.taint(*b).is_some());
        let into = if ctx_bind || decoder {
            target(a.first())
        } else if unmarshal {
            target(a.get(1))
        } else {
            None
        };
        if let Some(name) = into {
            self.mark(&name, Some(Taint { source: format!("{callee}(…)"), line: call.start_position().row + 1 }), false);
        }
    }
}

pub fn args(call: Node<'_>) -> Vec<Node<'_>> {
    call.child_by_field_name("arguments")
        .map(|a| {
            let mut c = a.walk();
            a.named_children(&mut c).collect()
        })
        .unwrap_or_default()
}

fn list(n: Node<'_>) -> Vec<Node<'_>> {
    if n.kind() == "expression_list" {
        let mut c = n.walk();
        n.named_children(&mut c).collect()
    } else {
        vec![n]
    }
}

pub fn is_literal(n: Node<'_>) -> bool {
    matches!(n.kind(), "interpreted_string_literal" | "raw_string_literal" | "int_literal" | "float_literal" | "rune_literal" | "true" | "false" | "nil")
}

fn is_sanitizer(callee: &str) -> bool {
    re!(r"^(strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|filepath\.Base|path\.Base|url\.(PathEscape|QueryEscape)|html\.EscapeString|template\.(HTMLEscapeString|JSEscapeString|URLQueryEscaper|HTMLEscaper)|uuid\.(Parse|MustParse)|bluemonday\.\w+|regexp\.QuoteMeta|len)$")
        .is_match(callee)
}

fn is_propagator(callee: &str) -> bool {
    re!(r"^(fmt\.(Sprintf|Sprint|Sprintln|Errorf)|strings\.\w+|bytes\.\w+|url\.(QueryUnescape|PathUnescape|Parse|ParseRequestURI)|filepath\.(Join|Clean|Abs|FromSlash|ToSlash)|path\.(Join|Clean)|strconv\.(Quote|Itoa|FormatInt)|html\.UnescapeString|append|base64\.\w+Encoding\.DecodeString)$").is_match(callee)
}

/// File functions whose result carries a tainted argument. A function named like a
/// sanitizer keeps that status only if its body actually transforms the value.
pub fn passthrough_functions(src: &Src<'_>, root: Node<'_>) -> BTreeSet<String> {
    let none = BTreeSet::new();
    let mut out = BTreeSet::new();
    for f in descendants(root, "function_declaration") {
        let (Some(name), Some(params), Some(body)) = (f.child_by_field_name("name"), f.child_by_field_name("parameters"), f.child_by_field_name("body")) else {
            continue;
        };
        let name = src.of(name).to_owned();
        let mut s = Scope::new(src, Roles::default(), &none);
        for p in param_names(src, params) {
            s.mark(&p, Some(Taint { source: format!("argument of {name}"), line: 0 }), false);
        }
        s.propagate(body);
        let returns_taint = descendants(body, "return_statement").into_iter().any(|r| {
            let mut c = r.walk();
            let kids: Vec<Node<'_>> = r.named_children(&mut c).collect();
            kids.into_iter().any(|e| s.taint(e).is_some())
        });
        let named_sanitizer = re!(r"(?i)sanitiz|escape|clean|validat|safe").is_match(&name);
        let transforms =
            re!(r"strings\.(Replace|ReplaceAll|Map|Trim\w*)|regexp\.|html\.Escape|url\.\w*Escape|strconv\.|filepath\.Base|bluemonday|template\.\w*Escape")
                .is_match(src.of(body));
        if returns_taint && (!named_sanitizer || !transforms) {
            out.insert(name);
        }
    }
    out
}
