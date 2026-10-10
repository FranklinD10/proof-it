//! Model IR → Lean 4 source.
//!
//! Output is meant to be read: named variables, the source meaning of every
//! variable in a comment, one hypothesis per line. Generated files import
//! nothing, so the trusted base is the Lean kernel plus Lean's core (`Init`).

use crate::eval::{Assignment, Value};
use crate::ir::*;
use proof_it_core::facts::CmpOp;
use std::collections::HashMap;
use std::fmt::Write as _;

const RESERVED: &[&str] = &[
    "at",
    "by",
    "do",
    "then",
    "else",
    "if",
    "let",
    "in",
    "have",
    "show",
    "from",
    "fun",
    "match",
    "with",
    "end",
    "open",
    "namespace",
    "section",
    "import",
    "where",
    "deriving",
    "instance",
    "structure",
    "class",
    "inductive",
    "for",
    "unless",
    "return",
    "mut",
    "Type",
    "Prop",
    "Sort",
    "forall",
    "exists",
    "variable",
    "universe",
    "axiom",
    "example",
    "abbrev",
    "macro",
    "syntax",
    "notation",
    "local",
    "private",
    "protected",
    "partial",
    "unsafe",
    "noncomputable",
    "sorry",
    "admit",
    "theorem",
    "def",
    "lemma",
    "opaque",
    "true",
    "false",
    "True",
    "False",
    "decide",
    "this",
    "mutual",
    "calc",
    "suffices",
    "obtain",
    "nomatch",
    "nofun",
    "rfl",
    "omega",
    "simp",
];

/// Lean identifier for a model variable / def / theorem name.
pub fn ident(s: &str) -> String {
    let mut id: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    while id.contains("__") {
        id = id.replace("__", "_");
    }
    let id = id.trim_matches('_');
    let mut id = if id.is_empty() { "x".to_owned() } else { id.to_owned() };
    if id.starts_with(|c: char| c.is_ascii_digit()) {
        id.insert(0, 'v');
    }
    let looks_like_hyp = id.len() > 1 && id.starts_with('h') && id[1..].bytes().all(|b| b.is_ascii_digit());
    if RESERVED.contains(&id.as_str()) || looks_like_hyp {
        id.push('_');
    }
    id
}

/// Enum constructor: preserves source spelling via «» when needed.
pub fn ctor(member: &str) -> String {
    let clean: String = member.chars().map(|c| if matches!(c, '«' | '»' | '\n' | '\r') { '_' } else { c }).collect();
    let plain = clean.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if plain && !RESERVED.contains(&clean.as_str()) { clean } else { format!("«{clean}»") }
}

pub fn type_name(name: &str) -> String {
    let id = ident(name);
    if id.starts_with(|c: char| c.is_ascii_uppercase()) { id } else { format!("T{id}") }
}

fn sort_lean(s: &Sort) -> String {
    match s {
        Sort::Int => "Int".into(),
        Sort::Nat => "Nat".into(),
        Sort::Bool => "Bool".into(),
        Sort::Enum { name } => type_name(name),
    }
}

struct Ctx<'o> {
    sorts: HashMap<String, Sort>,
    names: HashMap<String, String>,
    defs: HashMap<&'o str, &'o Def>,
    subst: Option<&'o Assignment>,
}

fn literal(v: &Value, s: &Sort) -> String {
    match (s, v) {
        (Sort::Bool, Value::Bool(b)) => b.to_string(),
        (Sort::Int, Value::Int(i)) => format!("({i} : Int)"),
        (Sort::Nat, Value::Int(i)) => format!("({i} : Nat)"),
        (Sort::Enum { name }, Value::Sym(m)) => format!("{}.{}", type_name(name), ctor(m)),
        (_, Value::Int(i)) => i.to_string(),
        (_, Value::Bool(b)) => b.to_string(),
        (_, Value::Sym(m)) => ctor(m),
    }
}

impl Ctx<'_> {
    fn sort_of(&self, e: &Expr) -> Option<Sort> {
        match e {
            Expr::Var { name } => self.sorts.get(name).cloned(),
            Expr::Int { .. } => Some(Sort::Int),
            Expr::EnumLit { enum_name, .. } => Some(Sort::Enum { name: enum_name.clone() }),
            Expr::Arith { a, b, .. } => self.sort_of(a).or_else(|| self.sort_of(b)),
            _ => Some(Sort::Bool),
        }
    }

    fn term(&self, e: &Expr, hint: Option<&Sort>) -> String {
        match e {
            Expr::Var { name } => {
                if let (Some(sub), Some(s)) = (self.subst, self.sorts.get(name))
                    && let Some(v) = sub.get(name)
                {
                    return literal(v, s);
                }
                self.names.get(name).cloned().unwrap_or_else(|| ident(name))
            }
            Expr::Int { v } => match hint {
                Some(Sort::Nat) if *v >= 0 => format!("({v} : Nat)"),
                _ => format!("({v} : Int)"),
            },
            Expr::Bool { v } => v.to_string(),
            Expr::EnumLit { enum_name, member } => {
                format!("{}.{}", type_name(enum_name), ctor(member))
            }
            Expr::Arith { op, a, b } => {
                let h = self.sort_of(e).or_else(|| hint.cloned());
                let o = match op {
                    Arith::Add => "+",
                    Arith::Sub => "-",
                    Arith::Mul => "*",
                };
                format!("({} {o} {})", self.term(a, h.as_ref()), self.term(b, h.as_ref()))
            }
            Expr::Call { f, args } => {
                let params = self.defs.get(f.as_str()).map(|d| d.params.clone()).unwrap_or_default();
                let rendered: Vec<String> = args.iter().enumerate().map(|(i, a)| self.term(a, params.get(i).map(|p| &p.1))).collect();
                format!("({} {})", ident(f), rendered.join(" "))
            }
            _ => format!("(decide {})", self.prop(e)),
        }
    }

    fn prop(&self, e: &Expr) -> String {
        match e {
            Expr::Var { .. } | Expr::Call { .. } => format!("({} = true)", self.term(e, None)),
            Expr::Bool { v } => {
                if *v {
                    "True".into()
                } else {
                    "False".into()
                }
            }
            Expr::Not { e } => format!("¬ {}", self.prop(e)),
            Expr::And { es } if es.is_empty() => "True".into(),
            Expr::And { es } => format!("({})", es.iter().map(|x| self.prop(x)).collect::<Vec<_>>().join(" ∧ ")),
            Expr::Or { es } if es.is_empty() => "False".into(),
            Expr::Or { es } => format!("({})", es.iter().map(|x| self.prop(x)).collect::<Vec<_>>().join(" ∨ ")),
            Expr::Cmp { op, a, b } => {
                let h = self.sort_of(a).filter(|s| *s != Sort::Bool || matches!(**a, Expr::Var { .. })).or_else(|| self.sort_of(b));
                let o = match op {
                    CmpOp::Eq => "=",
                    CmpOp::Ne => "≠",
                    CmpOp::Lt => "<",
                    CmpOp::Le => "≤",
                    CmpOp::Gt => ">",
                    CmpOp::Ge => "≥",
                };
                format!("({} {o} {})", self.term(a, h.as_ref()), self.term(b, h.as_ref()))
            }
            Expr::Int { .. } | Expr::EnumLit { .. } | Expr::Arith { .. } => {
                format!("({} = true)", self.term(e, None))
            }
        }
    }
}

fn make_ctx<'o>(ob: &'o Obligation, subst: Option<&'o Assignment>) -> Ctx<'o> {
    let mut names = HashMap::new();
    let mut used = std::collections::HashSet::new();
    for v in &ob.vars {
        let mut n = ident(&v.name);
        while !used.insert(n.clone()) {
            n.push('\'');
        }
        names.insert(v.name.clone(), n);
    }
    Ctx {
        sorts: ob.vars.iter().map(|v| (v.name.clone(), v.sort.clone())).collect(),
        names,
        defs: ob.defs.iter().map(|d| (d.name.as_str(), d)).collect(),
        subst,
    }
}

fn emit_enum(e: &EnumDecl) -> String {
    let mut seen = std::collections::HashSet::new();
    let ctors: Vec<String> = e.members.iter().filter(|m| seen.insert(ctor(m))).map(|m| format!("  | {}", ctor(m))).collect();
    format!("inductive {} where\n{}\n  deriving DecidableEq, Repr\n", type_name(&e.name), ctors.join("\n"))
}

fn emit_def(d: &Def, ob: &Obligation, ctx: &Ctx<'_>) -> String {
    let sig: Vec<String> = d.params.iter().map(|(_, s)| sort_lean(s)).collect();
    match &d.body {
        DefBody::Table { rows, origins } => {
            let mut seen = std::collections::HashSet::new();
            let mut lines = Vec::new();
            for (i, row) in rows.iter().enumerate() {
                if !seen.insert(row.clone()) {
                    continue;
                }
                let pats: Vec<String> = row.iter().map(|m| format!(".{}", ctor(m))).collect();
                let origin = origins.get(i).and_then(Option::as_ref).map(|o| format!("  -- {}:{}", o.file, o.line)).unwrap_or_default();
                lines.push(format!("  | {} => true{origin}", pats.join(", ")));
            }
            let space: usize = d
                .params
                .iter()
                .map(|(_, s)| match s {
                    Sort::Enum { name } => ob.enums.iter().find(|e| &e.name == name).map_or(1, |e| e.members.len()),
                    _ => usize::MAX,
                })
                .fold(1usize, usize::saturating_mul);
            let fallback = if seen.len() < space { format!("\n  | {} => false", vec!["_"; d.params.len()].join(", ")) } else { String::new() };
            format!("def {} : {} → Bool\n{}{fallback}\n", ident(&d.name), sig.join(" → "), lines.join("\n"))
        }
        DefBody::Expr { e } => {
            let mut inner = Ctx { sorts: ctx.sorts.clone(), names: ctx.names.clone(), defs: ctx.defs.clone(), subst: None };
            for (p, s) in &d.params {
                inner.sorts.insert(p.clone(), s.clone());
                inner.names.insert(p.clone(), ident(p));
            }
            let params: Vec<String> = d.params.iter().map(|(p, s)| format!("({} : {})", ident(p), sort_lean(s))).collect();
            format!("def {} {} : Bool :=\n  decide {}\n", ident(&d.name), params.join(" "), inner.prop(e))
        }
    }
}

fn emit_extra(x: &LeanExtra) -> (String, String) {
    match x {
        LeanExtra::Absorbing { enum_name, relation, state, theorem } => {
            let t = type_name(enum_name);
            let r = ident(relation);
            let s = format!("{t}.{}", ctor(state));
            let th = ident(theorem);
            (
                format!(
                    "/-- Reflexive-transitive closure of `{r}`: sequences of valid transitions. -/\ninductive Reachable : {t} → {t} → Prop\n  | refl (s : {t}) : Reachable s s\n  | step {{a b c : {t}}} : {r} a b = true → Reachable b c → Reachable a c\n\n/-- Once in {state}, every sequence of valid transitions stays in {state}. -/\ntheorem {th} : ∀ (a t : {t}), Reachable a t → a = {s} → t = {s} := by\n  intro a t h\n  induction h with\n  | refl => exact id\n  | step hv _ _ =>\n    intro ha\n    subst ha\n    rename_i b _ _\n    cases b <;> simp [{r}] at hv\n"
                ),
                th,
            )
        }
    }
}

pub struct Emitted {
    pub source: String,
    /// Fully qualified theorems whose axioms must be audited.
    pub theorems: Vec<String>,
}

fn preamble(ob: &Obligation, header: &[String], ns: &str, ctx: &Ctx<'_>) -> String {
    let mut s = String::new();
    for h in header {
        let _ = writeln!(s, "-- {}", h.replace('\n', " "));
    }
    let _ = writeln!(s, "\nnamespace {ns}\n");
    for e in &ob.enums {
        let _ = writeln!(s, "{}", emit_enum(e));
    }
    for d in &ob.defs {
        let _ = writeln!(s, "{}", emit_def(d, ob, ctx));
    }
    s
}

const MAX_CASE_SPLIT: usize = 4096;

/// The default proof: split finite variables, then `simp_all` and `omega`.
pub fn default_tactic(ob: &Obligation) -> String {
    let ctx = make_ctx(ob, None);
    let finite: Vec<&ModelVar> = ob.vars.iter().filter(|v| matches!(v.sort, Sort::Bool | Sort::Enum { .. })).collect();
    let size = finite
        .iter()
        .map(|v| match &v.sort {
            Sort::Bool => 2usize,
            Sort::Enum { name } => ob.enums.iter().find(|e| &e.name == name).map_or(1, |e| e.members.len()),
            _ => 1,
        })
        .fold(1usize, usize::saturating_mul);
    let mut parts: Vec<String> = if size <= MAX_CASE_SPLIT { finite.iter().map(|v| format!("cases {}", ctx.names[&v.name])).collect() } else { vec![] };
    let simps: Vec<String> = ob.defs.iter().map(|d| ident(&d.name)).collect();
    parts.push(if simps.is_empty() { "(try simp_all)".into() } else { format!("(try simp_all [{}])", simps.join(", ")) });
    parts.push("(try omega)".into());
    parts.join(" <;> ")
}

/// `∀ vars, hyps → conclusion`, proved by `tactic` (default or an untrusted hint).
pub fn emit_obligation(ob: &Obligation, header: &[String], ns: &str, tactic: Option<&str>) -> Emitted {
    let ctx = make_ctx(ob, None);
    let thm = ident(&ob.theorem);
    let binders: Vec<String> = ob.vars.iter().map(|v| format!("({} : {})", ctx.names[&v.name], sort_lean(&v.sort))).collect();
    let mut s = preamble(ob, header, ns, &ctx);
    let _ = writeln!(s, "/-\n  {}\n-/", ob.statement.replace("-/", "- /"));
    let _ = writeln!(s, "-- Model variables:");
    for v in &ob.vars {
        let loc = v.location.as_ref().map(|l| format!(" ({}:{})", l.file, l.line)).unwrap_or_default();
        let _ = writeln!(
            s,
            "--   {} : {} — {}{}{loc}",
            ctx.names[&v.name],
            sort_lean(&v.sort),
            v.meaning.replace('\n', " "),
            if v.opaque { " [OPAQUE]" } else { "" }
        );
    }
    let _ = writeln!(s, "theorem {thm} :");
    let _ = writeln!(s, "    ∀ {},", if binders.is_empty() { "(_u : Unit)".to_owned() } else { binders.join(" ") });
    for (i, h) in ob.hypotheses.iter().enumerate() {
        let loc = h.location.as_ref().map(|l| format!(" ({}:{})", l.file, l.line)).unwrap_or_default();
        let _ = writeln!(s, "      {} →  -- h{}: {}{loc}", ctx.prop(&h.expr), i + 1, h.label.replace('\n', " "));
    }
    let _ = writeln!(s, "      {} := by", ctx.prop(&ob.conclusion));
    let mut intros: Vec<String> = if binders.is_empty() { vec!["_u".into()] } else { ob.vars.iter().map(|v| ctx.names[&v.name].clone()).collect() };
    intros.extend((1..=ob.hypotheses.len()).map(|i| format!("h{i}")));
    let _ = writeln!(s, "  intro {}", intros.join(" "));
    let tac = tactic.map_or_else(|| default_tactic(ob), str::to_owned);
    for line in tac.lines() {
        let _ = writeln!(s, "  {line}");
    }
    let mut theorems = vec![format!("{ns}.{thm}")];
    for x in &ob.extras {
        let (src, th) = emit_extra(x);
        let _ = writeln!(s, "\n{src}");
        theorems.push(format!("{ns}.{th}"));
    }
    let _ = writeln!(s, "\nend {ns}\n");
    for t in &theorems {
        let _ = writeln!(s, "#print axioms {t}");
    }
    Emitted { source: s, theorems }
}

/// Certificate that `asg` violates the obligation in the model:
/// `∀ opaque, (h1 ∧ … ∧ ¬ conclusion)` with non-opaque variables substituted,
/// proved by `decide` after splitting the finite opaque variables.
/// With `suffix = "_witness"` and conclusion `False` it certifies non-vacuity.
pub fn emit_certificate(ob: &Obligation, asg: &Assignment, header: &[String], ns: &str, suffix: &str) -> Emitted {
    let opaque: Vec<&ModelVar> = ob.vars.iter().filter(|v| v.opaque).collect();
    let subst: Assignment = ob.vars.iter().filter(|v| !v.opaque).filter_map(|v| asg.get(&v.name).map(|x| (v.name.clone(), x.clone()))).collect();
    let ctx = make_ctx(ob, Some(&subst));
    let thm = format!("{}{suffix}", ident(&ob.theorem));
    let mut s = preamble(ob, header, ns, &ctx);
    let _ = writeln!(s, "-- Assignment:");
    for v in ob.vars.iter().filter(|v| !v.opaque) {
        let _ = writeln!(
            s,
            "--   {} := {}  ({})",
            ctx.names[&v.name],
            subst.get(&v.name).map_or("?".to_owned(), |x| serde_json::to_string(x).unwrap_or_default()),
            v.meaning.replace('\n', " ")
        );
    }
    let mut conj: Vec<String> = ob.hypotheses.iter().map(|h| ctx.prop(&h.expr)).collect();
    conj.push(format!("¬ {}", ctx.prop(&ob.conclusion)));
    let body = conj.join(" ∧\n      ");
    let _ = writeln!(s, "theorem {thm} :");
    if opaque.is_empty() {
        let _ = writeln!(s, "      {body} := by\n  decide");
    } else {
        let binders: Vec<String> = opaque.iter().map(|v| format!("({} : {})", ctx.names[&v.name], sort_lean(&v.sort))).collect();
        let names: Vec<&str> = opaque.iter().map(|v| ctx.names[&v.name].as_str()).collect();
        let splits: Vec<String> = names.iter().map(|n| format!("cases {n}")).collect();
        let _ = writeln!(s, "    ∀ {},\n      {body} := by\n  intro {}\n  {} <;> decide", binders.join(" "), names.join(" "), splits.join(" <;> "));
    }
    let _ = writeln!(s, "\nend {ns}\n\n#print axioms {ns}.{thm}");
    Emitted { source: s, theorems: vec![format!("{ns}.{thm}")] }
}

/// Constructs that would let a "proof" bypass the kernel or assume what it proves.
pub const FORBIDDEN: &[&str] = &[
    "sorry",
    "admit",
    "axiom",
    "unsafe",
    "native_decide",
    "implemented_by",
    "extern",
    "opaque",
    "debug.skipKernelTC",
    "ofReduceBool",
    "#eval",
    "partial",
    "decreasing_by",
    "termination_by",
    "@[csimp]",
    "set_option",
];

/// Forbidden constructs present in `source`, ignoring comments and «quoted» names.
pub fn forbidden_constructs(source: &str) -> Vec<&'static str> {
    let mut stripped = String::with_capacity(source.len());
    let b = source.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    let mut in_line = false;
    let mut in_quote = false;
    while i < b.len() {
        let rest = &source[i..];
        if in_line {
            if b[i] == b'\n' {
                in_line = false;
                stripped.push('\n');
            }
            i += rest.chars().next().map_or(1, char::len_utf8);
            continue;
        }
        if depth > 0 {
            if rest.starts_with("-/") {
                depth -= 1;
                i += 2;
            } else if rest.starts_with("/-") {
                depth += 1;
                i += 2;
            } else {
                i += rest.chars().next().map_or(1, char::len_utf8);
            }
            continue;
        }
        if in_quote {
            if rest.starts_with('»') {
                in_quote = false;
                stripped.push(' ');
            }
            i += rest.chars().next().map_or(1, char::len_utf8);
            continue;
        }
        if rest.starts_with("--") {
            in_line = true;
            i += 2;
        } else if rest.starts_with("/-") {
            depth = 1;
            i += 2;
        } else if rest.starts_with('«') {
            in_quote = true;
            i += '«'.len_utf8();
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            stripped.push(c);
            i += c.len_utf8();
        }
    }
    let word_char = |c: char| c.is_alphanumeric() || c == '_' || c == '.' || c == '\'';
    FORBIDDEN
        .iter()
        .copied()
        .filter(|f| {
            stripped.match_indices(f).any(|(pos, _)| {
                let before = stripped[..pos].chars().next_back();
                let after = stripped[pos + f.len()..].chars().next();
                let start_ok = f.starts_with(['#', '@']) || before.is_none_or(|c| !word_char(c));
                let end_ok = after.is_none_or(|c| !word_char(c) || f.ends_with(']'));
                start_ok && end_ok
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idents_are_safe() {
        assert_eq!(ident("from.balance"), "from_balance");
        assert_eq!(ident("theorem"), "theorem_");
        assert_eq!(ident("h1"), "h1_");
        assert_eq!(ident("1x"), "v1x");
        assert_eq!(ctor("IN_PROGRESS"), "IN_PROGRESS");
        assert_eq!(ctor("in progress"), "«in progress»");
        assert_eq!(ctor("sorry"), "«sorry»");
    }

    #[test]
    fn forbidden_scan_ignores_comments_and_quotes() {
        assert!(forbidden_constructs("-- sorry\n/- admit -/\ninductive S | «sorry»").is_empty());
        assert_eq!(forbidden_constructs("theorem x : True := by sorry"), vec!["sorry"]);
        assert_eq!(forbidden_constructs("axiom bad : False"), vec!["axiom"]);
        assert_eq!(forbidden_constructs("by native_decide"), vec!["native_decide"]);
        assert_eq!(forbidden_constructs("set_option debug.skipKernelTC true"), vec!["debug.skipKernelTC", "set_option"]);
        assert!(forbidden_constructs("theorem sorryless : True := trivial").is_empty());
        // multi-byte characters in comments, quotes and code
        assert!(forbidden_constructs("-- Property: X — y\n/- é — -/ theorem t : «état — x» = 1").is_empty());
        assert_eq!(forbidden_constructs("-- ok — fine\ntheorem t : True := by sorry"), vec!["sorry"]);
    }
}
