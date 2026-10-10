//! The formal model IR: a small, total, first-order language over integers,
//! naturals (identities, equality only), booleans and finite enumerations.
//! Extractors translate facts into it; the Lean emitter and the evaluator give
//! it the SAME semantics, which is what lets a counterexample found by search
//! be re-checked by the Lean kernel.

use proof_it_core::facts::CmpOp;
use proof_it_core::types::SourceLocation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Sort {
    Int,
    /// Identities: only compared for equality.
    Nat,
    Bool,
    Enum {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumDecl {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arith {
    Add,
    Sub,
    Mul,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Expr {
    Var { name: String },
    Int { v: i64 },
    Bool { v: bool },
    EnumLit { enum_name: String, member: String },
    Not { e: Box<Expr> },
    And { es: Vec<Expr> },
    Or { es: Vec<Expr> },
    Cmp { op: CmpOp, a: Box<Expr>, b: Box<Expr> },
    Arith { op: Arith, a: Box<Expr>, b: Box<Expr> },
    Call { f: String, args: Vec<Expr> },
}

pub fn var(n: &str) -> Expr {
    Expr::Var { name: n.to_owned() }
}
pub fn int(v: i64) -> Expr {
    Expr::Int { v }
}
pub fn not(e: Expr) -> Expr {
    Expr::Not { e: Box::new(e) }
}
pub fn and(mut es: Vec<Expr>) -> Expr {
    if es.len() == 1 { es.remove(0) } else { Expr::And { es } }
}
pub fn or(mut es: Vec<Expr>) -> Expr {
    if es.len() == 1 { es.remove(0) } else { Expr::Or { es } }
}
pub fn cmp(op: CmpOp, a: Expr, b: Expr) -> Expr {
    Expr::Cmp { op, a: Box::new(a), b: Box::new(b) }
}
pub fn eq(a: Expr, b: Expr) -> Expr {
    cmp(CmpOp::Eq, a, b)
}
pub fn arith(op: Arith, a: Expr, b: Expr) -> Expr {
    Expr::Arith { op, a: Box::new(a), b: Box::new(b) }
}
pub fn enum_lit(enum_name: &str, member: &str) -> Expr {
    Expr::EnumLit { enum_name: enum_name.to_owned(), member: member.to_owned() }
}

impl Expr {
    pub fn vars(&self, out: &mut Vec<String>) {
        match self {
            Expr::Var { name } => out.push(name.clone()),
            Expr::Not { e } => e.vars(out),
            Expr::And { es } | Expr::Or { es } => es.iter().for_each(|e| e.vars(out)),
            Expr::Cmp { a, b, .. } | Expr::Arith { a, b, .. } => {
                a.vars(out);
                b.vars(out);
            }
            Expr::Call { args, .. } => args.iter().for_each(|e| e.vars(out)),
            _ => {}
        }
    }
    pub fn int_literals(&self, out: &mut Vec<i64>) {
        match self {
            Expr::Int { v } => out.push(*v),
            Expr::Not { e } => e.int_literals(out),
            Expr::And { es } | Expr::Or { es } => es.iter().for_each(|e| e.int_literals(out)),
            Expr::Cmp { a, b, .. } | Expr::Arith { a, b, .. } => {
                a.int_literals(out);
                b.int_literals(out);
            }
            Expr::Call { args, .. } => args.iter().for_each(|e| e.int_literals(out)),
            _ => {}
        }
    }
    /// Source-like rendering for reports.
    pub fn show(&self) -> String {
        match self {
            Expr::Var { name } => name.clone(),
            Expr::Int { v } => v.to_string(),
            Expr::Bool { v } => v.to_string(),
            Expr::EnumLit { member, .. } => format!("{member:?}"),
            Expr::Not { e } => format!("!({})", e.show()),
            Expr::And { es } if es.is_empty() => "true".into(),
            Expr::And { es } => es.iter().map(Expr::show).collect::<Vec<_>>().join(" && "),
            Expr::Or { es } if es.is_empty() => "false".into(),
            Expr::Or { es } => format!("({})", es.iter().map(Expr::show).collect::<Vec<_>>().join(" || ")),
            Expr::Cmp { op, a, b } => {
                let o = match op {
                    CmpOp::Eq => "==",
                    CmpOp::Ne => "!=",
                    CmpOp::Lt => "<",
                    CmpOp::Le => "<=",
                    CmpOp::Gt => ">",
                    CmpOp::Ge => ">=",
                };
                format!("{} {o} {}", a.show(), b.show())
            }
            Expr::Arith { op, a, b } => {
                let o = match op {
                    Arith::Add => "+",
                    Arith::Sub => "-",
                    Arith::Mul => "*",
                };
                format!("({} {o} {})", a.show(), b.show())
            }
            Expr::Call { f, args } => format!("{f}({})", args.iter().map(Expr::show).collect::<Vec<_>>().join(", ")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum DefBody {
    /// Enum-only parameters: tuples (member names) for which the def is true.
    Table {
        rows: Vec<Vec<String>>,
        origins: Vec<Option<SourceLocation>>,
    },
    Expr {
        e: Expr,
    },
}

/// A Bool-valued definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Def {
    pub name: String,
    pub params: Vec<(String, Sort)>,
    pub body: DefBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelVar {
    pub name: String,
    pub sort: Sort,
    /// What the variable stands for in the source.
    pub meaning: String,
    /// Abstracts code Proof-It could not interpret. A violation counts as
    /// VIOLATED only if it holds for every value of every opaque variable.
    #[serde(default)]
    pub opaque: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
}

impl ModelVar {
    pub fn new(name: &str, sort: Sort, meaning: impl Into<String>) -> Self {
        Self { name: name.to_owned(), sort, meaning: meaning.into(), opaque: false, location: None }
    }
    pub fn opaque(name: &str, sort: Sort, meaning: impl Into<String>) -> Self {
        Self { opaque: true, ..Self::new(name, sort, meaning) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub expr: Expr,
    pub label: String,
    /// An assumption Proof-It makes about code it cannot see or interpret
    /// (as opposed to a fact read from the code). A theorem whose conclusion
    /// follows from assumptions alone proves nothing about the code.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub assumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum LeanExtra {
    /// Multi-step absorption of a terminal state under the transition relation.
    Absorbing { enum_name: String, relation: String, state: String, theorem: String },
}

/// ∀ vars, hypotheses → conclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Obligation {
    pub theorem: String,
    pub property_id: String,
    pub statement: String,
    pub enums: Vec<EnumDecl>,
    pub defs: Vec<Def>,
    pub vars: Vec<ModelVar>,
    pub hypotheses: Vec<Hypothesis>,
    pub conclusion: Expr,
    #[serde(default)]
    pub extras: Vec<LeanExtra>,
    /// What must be satisfiable for the theorem to be meaningful (non-vacuity).
    /// `None` = all hypotheses. A safety property whose own antecedent is
    /// unsatisfiable (e.g. "every transition out of a terminal state…" when
    /// there are none) is not vacuous; an empty transition relation is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meaningful_if: Option<Vec<Hypothesis>>,
}
