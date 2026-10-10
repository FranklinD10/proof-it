//! Extractors: language-neutral facts → model obligations.

pub mod authz;
pub mod ledger;
pub mod state_machine;

use crate::eval::Assignment;
use crate::ir::Obligation;
use proof_it_core::config::{Config, OrgPolicy};
use proof_it_core::facts::{CmpOp, Cond, ProgramFacts, Val};
use proof_it_core::property::{Extractor, Property};
use proof_it_core::types::{CounterexampleStep, ProofStatus, SourceLocation, SpecSource};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct ExtractContext<'x> {
    pub facts: &'x ProgramFacts,
    pub config: &'x Config,
    pub org: &'x OrgPolicy,
}

/// How to execute a counterexample against the implementation (data only, so
/// it can be saved and replayed later with `proof-it replay`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReplaySpec {
    StateTransition { module: String, field: String, edges: Vec<EdgeReplay> },
    Ledger { module: String, function: String, params: Vec<String>, receivers: Vec<ReceiverReplay>, property: LedgerProperty },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeReplay {
    pub function: String,
    pub receiver_param: usize,
    pub value_param: Option<usize>,
    pub field: String,
    pub from: Option<Vec<String>>,
    pub to: Option<Vec<String>>,
    /// Parameter values that satisfy simple preconditions on the path
    /// (e.g. `if (role !== "admin") throw` ⇒ role = "admin"), so replay reaches the write.
    #[serde(default)]
    pub param_values: Vec<(usize, serde_json::Value)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiverReplay {
    pub param: usize,
    pub field: String,
    pub initial_var: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerProperty {
    Conservation,
    NonNegative,
}

pub type TraceFn = Arc<dyn Fn(&Assignment) -> Vec<CounterexampleStep> + Send + Sync>;

/// One property instantiated at one code target.
#[derive(Clone)]
pub struct Extraction {
    pub property_id: String,
    pub target: String,
    pub location: Option<SourceLocation>,
    pub obligation: Option<Obligation>,
    /// When there is no obligation: the status and why.
    pub status: Option<ProofStatus>,
    pub reason: Option<String>,
    pub assumptions: Vec<String>,
    pub spec_source: SpecSource,
    pub trace: Option<TraceFn>,
    pub replay: Option<ReplaySpec>,
    pub model_summary: Vec<String>,
    /// Files whose code the model depends on (for change impact).
    pub files: Vec<String>,
}

impl Extraction {
    pub fn not_modeled(p: &Property, target: &str, status: ProofStatus, reason: impl Into<String>, location: Option<SourceLocation>) -> Self {
        Self {
            property_id: p.id().to_owned(),
            target: target.to_owned(),
            location: location.clone(),
            obligation: None,
            status: Some(status),
            reason: Some(reason.into()),
            assumptions: p.spec.assumptions.clone(),
            spec_source: p.source,
            trace: None,
            replay: None,
            model_summary: vec![],
            files: location.map(|l| vec![l.file]).unwrap_or_default(),
        }
    }
}

pub fn run_extractor(p: &Property, ctx: &ExtractContext<'_>) -> Vec<Extraction> {
    match p.spec.formal.as_ref().map(|f| f.extractor) {
        Some(Extractor::StateMachineTerminal | Extractor::StateMachineForbidden) => state_machine::extract(p, ctx),
        Some(Extractor::AuthzOwnership | Extractor::AuthzAdmin | Extractor::AuthzWrite) => authz::extract(p, ctx),
        Some(Extractor::LedgerConservation | Extractor::LedgerNonNegative) => ledger::extract(p, ctx),
        None => vec![],
    }
}

/// Render a condition in source-like syntax for traces and gate labels.
pub fn show_cond(c: &Cond) -> String {
    fn v(x: &Val) -> String {
        match x {
            Val::Path { path } => path.clone(),
            Val::Str { v } => format!("{v:?}"),
            Val::Int { v } => v.to_string(),
            Val::Float { text } => text.clone(),
            Val::Bool { v } => v.to_string(),
            Val::Null => "null".into(),
            Val::Undefined => "undefined".into(),
            Val::Len { path } => format!("{path}.length"),
            Val::Bin { op, l, r } => format!(
                "{} {} {}",
                v(l),
                match op {
                    proof_it_core::facts::ArithOp::Add => "+",
                    proof_it_core::facts::ArithOp::Sub => "-",
                    proof_it_core::facts::ArithOp::Mul => "*",
                    proof_it_core::facts::ArithOp::Div => "/",
                    proof_it_core::facts::ArithOp::Mod => "%",
                },
                v(r)
            ),
            Val::Neg { e } => format!("-{}", v(e)),
            Val::EnumMember { enum_name, member } => format!("{enum_name}.{member}"),
            Val::Call { callee, args } => format!("{callee}({})", args.iter().map(v).collect::<Vec<_>>().join(", ")),
            Val::Other { text, .. } => text.clone(),
        }
    }
    match c {
        Cond::Not { c } => format!("!({})", show_cond(c)),
        Cond::And { cs } => cs.iter().map(show_cond).collect::<Vec<_>>().join(" && "),
        Cond::Or { cs } => format!("({})", cs.iter().map(show_cond).collect::<Vec<_>>().join(" || ")),
        Cond::Cmp { op, l, r } => format!(
            "{} {} {}",
            v(l),
            match op {
                CmpOp::Eq => "===",
                CmpOp::Ne => "!==",
                CmpOp::Lt => "<",
                CmpOp::Le => "<=",
                CmpOp::Gt => ">",
                CmpOp::Ge => ">=",
            },
            v(r)
        ),
        Cond::Truthy { v: x } => v(x),
        Cond::InList { list, item } => format!("{list:?}.includes({})", v(item)),
        Cond::TableHas { table, key, item } => format!("{table}[{}].includes({})", v(key), v(item)),
        Cond::Call { text, .. } | Cond::Other { text, .. } => text.clone(),
    }
}

/// Last path segment, singularised: `this.emergencies` → `emergency`.
pub fn entity_of(path: &str) -> String {
    let last =
        path.split(['.', '[']).rfind(|p| !p.is_empty() && *p != "this" && !p.ends_with(']')).unwrap_or("entity").trim_start_matches('_').to_ascii_lowercase();
    if let Some(s) = last.strip_suffix("ies") {
        format!("{s}y")
    } else if let Some(s) = last.strip_suffix('s') {
        s.to_owned()
    } else {
        last
    }
}
