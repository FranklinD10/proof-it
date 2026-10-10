//! Ledger extraction (PAY-001 conservation, PAY-003 non-negativity):
//! symbolic execution of straight-line balance updates over unbounded integers.
//!
//! Anything outside the fragment — floating-point literals, division, values of
//! unknown calls, balance updates inside branches or loops — makes the model
//! incomplete, and the result is UNPROVEN with the exact construct and line.
//! Proof-It never guesses the semantics of code it did not model.

use super::{ExtractContext, Extraction, LedgerProperty, ReceiverReplay, ReplaySpec, show_cond};
use crate::eval::{Assignment, Value};
use crate::ir::*;
use proof_it_core::facts::*;
use proof_it_core::property::{Extractor, Property};
use proof_it_core::types::{CounterexampleStep, ProofStatus, SourceLocation};
use std::collections::BTreeMap;
use std::sync::Arc;

struct Unsupported(String);

#[derive(Default)]
struct Sym {
    balances: BTreeMap<String, Expr>,
    initial: BTreeMap<String, (String, String)>, // receiver → (initial var, field)
    locals: BTreeMap<String, Expr>,
    vars: BTreeMap<String, ModelVar>,
    guards: Vec<(Expr, String, SourceLocation)>,
    gates: usize,
    decreased: Vec<String>,
    increased: Vec<String>,
    updates: Vec<(String, SourceLocation)>,
    params: Vec<String>,
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
}

const AMOUNT_FIELDS: [&str; 8] = ["amount", "value", "qty", "quantity", "price", "cents", "fee", "total"];

impl Sym {
    fn var(&mut self, name: &str, meaning: String) -> Expr {
        self.vars.entry(name.to_owned()).or_insert_with(|| ModelVar::new(name, Sort::Int, meaning));
        var(name)
    }

    fn balance(&mut self, recv: &str, field: &str, loc: &SourceLocation) -> Expr {
        if let Some(e) = self.balances.get(recv) {
            return e.clone();
        }
        let name = format!("{}_{field}", sanitize(recv));
        self.initial.insert(recv.to_owned(), (name.clone(), field.to_owned()));
        let e = self.var(&name, format!("initial {recv}.{field}"));
        if let Some(v) = self.vars.get_mut(&name) {
            v.location = Some(loc.clone());
        }
        self.balances.insert(recv.to_owned(), e.clone());
        e
    }

    fn int(&mut self, v: &Val, loc: &SourceLocation) -> Result<Expr, Unsupported> {
        match v {
            Val::Int { v } => Ok(int(*v)),
            Val::Float { text } => Err(Unsupported(format!("non-integer literal {text} (floating-point arithmetic is not modeled)"))),
            Val::Neg { e } => Ok(arith(Arith::Sub, int(0), self.int(e, loc)?)),
            Val::Path { path } => {
                if let Some(l) = self.locals.get(path) {
                    return Ok(l.clone());
                }
                if self.params.iter().any(|p| p == path) {
                    return Ok(self.var(path, format!("parameter {path}")));
                }
                if let Some((recv, field)) = path.rsplit_once('.') {
                    if is_balance(field) {
                        return Ok(self.balance(recv, field, loc));
                    }
                    let head = path.split('.').next().unwrap_or("");
                    if self.params.iter().any(|p| p == head) && AMOUNT_FIELDS.iter().any(|f| field.to_ascii_lowercase().contains(f)) {
                        let name = sanitize(path);
                        return Ok(self.var(&name, format!("input {path}")));
                    }
                }
                Err(Unsupported(format!("value of `{path}` is not modeled")))
            }
            Val::Bin { op, l, r } => {
                let (a, b) = (self.int(l, loc)?, self.int(r, loc)?);
                match op {
                    ArithOp::Add => Ok(arith(Arith::Add, a, b)),
                    ArithOp::Sub => Ok(arith(Arith::Sub, a, b)),
                    ArithOp::Mul if matches!(a, Expr::Int { .. }) || matches!(b, Expr::Int { .. }) => Ok(arith(Arith::Mul, a, b)),
                    ArithOp::Mul => Err(Unsupported("non-linear multiplication is not modeled".into())),
                    ArithOp::Div | ArithOp::Mod => Err(Unsupported("division/remainder is not modeled".into())),
                }
            }
            Val::Call { callee, args } if matches!(callee.as_str(), "Math.round" | "Math.ceil") && args.len() == 1 => {
                Err(Unsupported(format!("`{callee}` rounding is not modeled")))
            }
            Val::Call { callee, .. } => Err(Unsupported(format!("value returned by `{callee}(...)` is not modeled"))),
            other => Err(Unsupported(format!("expression `{other:?}` is not modeled"))),
        }
    }

    fn cond(&mut self, c: &Cond, loc: &SourceLocation) -> Result<Expr, Unsupported> {
        match c {
            Cond::Not { c } => Ok(not(self.cond(c, loc)?)),
            Cond::And { cs } => Ok(and(cs.iter().map(|x| self.cond(x, loc)).collect::<Result<_, _>>()?)),
            Cond::Or { cs } => Ok(or(cs.iter().map(|x| self.cond(x, loc)).collect::<Result<_, _>>()?)),
            Cond::Cmp { op, l, r } => Ok(cmp(*op, self.int(l, loc)?, self.int(r, loc)?)),
            other => Err(Unsupported(format!("condition `{}` is not modeled", show_cond(other)))),
        }
    }
}

fn is_balance(field: &str) -> bool {
    matches!(field.to_ascii_lowercase().as_str(), "balance" | "balancecents" | "availablebalance" | "funds" | "credits" | "walletbalance" | "amountavailable")
}

fn execute(f: &LedgerFunctionFact) -> Result<Sym, (Unsupported, SourceLocation)> {
    let mut st = Sym { params: f.params.clone(), ..Sym::default() };
    for s in &f.stmts {
        match s {
            LedgerStmt::Let { name, value, location } => {
                // Non-integer bindings (DB handles, ...) are fine unless used in balance math later.
                if let Ok(e) = st.int(value, location) {
                    st.locals.insert(name.clone(), e);
                }
            }
            LedgerStmt::ExitGuard { cond, text, location } => match st.cond(cond, location) {
                Ok(c) => st.guards.push((not(c), format!("!({text})"), location.clone())),
                Err(_) => {
                    let mentions_value = cond.all_paths().iter().any(|p| st.params.iter().any(|q| p == q || p.starts_with(&format!("{q}."))));
                    if mentions_value {
                        st.gates += 1;
                        let g = format!("gate{}", st.gates);
                        st.vars.insert(g.clone(), ModelVar::opaque(&g, Sort::Bool, format!("unanalysed guard: !({text})")));
                        st.guards.push((var(&g), format!("!({text}) [not modeled]"), location.clone()));
                    }
                }
            },
            LedgerStmt::BalanceWrite { receiver, field, op, value, text, location } => {
                let cur = st.balance(receiver, field, location);
                let rhs = st.int(value, location).map_err(|u| (u, location.clone()))?;
                let next = match op {
                    AssignOp::Add => {
                        st.increased.push(receiver.clone());
                        arith(Arith::Add, cur, rhs)
                    }
                    AssignOp::Sub => {
                        st.decreased.push(receiver.clone());
                        arith(Arith::Sub, cur, rhs)
                    }
                    AssignOp::Set => {
                        if let Val::Bin { op: ArithOp::Sub, .. } = value {
                            st.decreased.push(receiver.clone());
                        }
                        if let Val::Bin { op: ArithOp::Add, .. } = value {
                            st.increased.push(receiver.clone());
                        }
                        rhs
                    }
                };
                st.balances.insert(receiver.clone(), next);
                st.updates.push((text.clone(), location.clone()));
            }
            LedgerStmt::Unsupported { reason, location } => {
                return Err((Unsupported(reason.clone()), location.clone()));
            }
            LedgerStmt::Return { .. } => break,
        }
    }
    Ok(st)
}

pub fn extract(p: &Property, ctx: &ExtractContext<'_>) -> Vec<Extraction> {
    let kind = match p.spec.formal.as_ref().map(|f| f.extractor) {
        Some(Extractor::LedgerConservation) => LedgerProperty::Conservation,
        Some(Extractor::LedgerNonNegative) => LedgerProperty::NonNegative,
        _ => return vec![],
    };
    let mut out = Vec::new();
    for m in &ctx.facts.modules {
        for f in &m.ledger_functions {
            let target = format!("{} ({}:{})", f.name, f.location.file, f.location.line);
            let st = match execute(f) {
                Ok(st) => st,
                Err((u, at)) => {
                    let mut e = Extraction::not_modeled(
                        p,
                        &target,
                        ProofStatus::Unproven,
                        format!(
                            "the implementation could not be mapped completely to the ledger model: {} at {}:{}. Do NOT interpret this as a bug.",
                            u.0, at.file, at.line
                        ),
                        Some(f.location.clone()),
                    );
                    e.model_summary = vec![format!("Function {} updates a balance but uses a construct outside the supported fragment.", f.name)];
                    out.push(e);
                    continue;
                }
            };
            let recvs: Vec<String> = st.initial.keys().cloned().collect();
            if kind == LedgerProperty::Conservation && (recvs.len() < 2 || st.decreased.is_empty() || st.increased.is_empty()) {
                let why = if recvs.len() < 2 {
                    "updates a single account (deposit/withdrawal): money legitimately enters or leaves the ledger"
                } else {
                    "does not move value between accounts"
                };
                out.push(Extraction::not_modeled(p, &target, ProofStatus::NotApplicable, why, Some(f.location.clone())));
                continue;
            }
            if kind == LedgerProperty::NonNegative && st.decreased.is_empty() {
                continue;
            }
            let mut hyps: Vec<Hypothesis> = st
                .guards
                .iter()
                .map(|(e, t, l)| Hypothesis { assumed: false, expr: e.clone(), label: format!("guard {t}"), location: Some(l.clone()) })
                .collect();
            let finals: Vec<Expr> = recvs.iter().filter_map(|r| st.balances.get(r).cloned()).collect();
            let initials: Vec<Expr> = recvs.iter().filter_map(|r| st.initial.get(r).map(|(n, _)| var(n))).collect();
            let sum = |xs: &[Expr]| xs.iter().skip(1).fold(xs[0].clone(), |a, b| arith(Arith::Add, a, b.clone()));
            let conclusion = match kind {
                LedgerProperty::Conservation => eq(sum(&finals), sum(&initials)),
                LedgerProperty::NonNegative => {
                    for r in recvs.iter().rev() {
                        if let Some((n, _)) = st.initial.get(r) {
                            hyps.insert(
                                0,
                                Hypothesis {
                                    assumed: false,
                                    expr: cmp(CmpOp::Ge, var(n), int(0)),
                                    label: format!("{r} starts non-negative (invariant)"),
                                    location: Some(f.location.clone()),
                                },
                            );
                        }
                    }
                    and(finals.iter().map(|x| cmp(CmpOp::Ge, x.clone(), int(0))).collect())
                }
            };
            let theorem = format!("{}_{}", p.spec.formal.as_ref().map_or("ledger", |x| x.theorem.as_str()), f.name);
            let statement = match kind {
                LedgerProperty::Conservation => format!("{} preserves the total balance of {{{}}} (unbounded integers).", f.name, recvs.join(", ")),
                LedgerProperty::NonNegative => {
                    format!("If all balances are non-negative before {}, they are non-negative after it (unbounded integers).", f.name)
                }
            };
            let ob = Obligation {
                theorem,
                property_id: p.id().to_owned(),
                statement,
                enums: vec![],
                defs: vec![],
                vars: st.vars.values().cloned().collect(),
                hypotheses: hyps,
                conclusion,
                extras: vec![],
                meaningful_if: None,
            };
            let summary = vec![
                format!(
                    "Symbolically executed {} balance update(s): {}.",
                    st.updates.len(),
                    st.updates.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join("; ")
                ),
                format!(
                    "Final balances: {}.",
                    recvs.iter().map(|r| format!("{r} = {}", st.balances.get(r).map(Expr::show).unwrap_or_default())).collect::<Vec<_>>().join(", ")
                ),
                format!(
                    "{} guard(s) become hypotheses{}.",
                    st.guards.len(),
                    if st.gates > 0 { format!(", {} of them opaque", st.gates) } else { String::new() }
                ),
            ];
            let mut assumptions = p.spec.assumptions.clone();
            if recvs.len() > 1 {
                assumptions.push("Source and destination are distinct objects (aliasing is checked by the attack engine, not the model).".into());
            }
            // Replay: every receiver and every non-balance variable must be a parameter.
            let replay = {
                let receivers: Option<Vec<ReceiverReplay>> = st
                    .initial
                    .iter()
                    .map(|(r, (n, field))| {
                        st.params.iter().position(|q| q == r).map(|i| ReceiverReplay { param: i, field: field.clone(), initial_var: n.clone() })
                    })
                    .collect();
                let others_ok =
                    st.vars.keys().all(|k| st.initial.values().any(|(n, _)| n == k) || st.vars.get(k).is_some_and(|v| v.opaque) || st.params.contains(k));
                match receivers {
                    Some(receivers) if f.exported && others_ok => Some(ReplaySpec::Ledger {
                        module: f.location.file.clone(),
                        function: f.name.clone(),
                        params: st.params.clone(),
                        receivers,
                        property: kind,
                    }),
                    _ => None,
                }
            };
            let guards = st.guards.clone();
            let updates = st.updates.clone();
            let initial = st.initial.clone();
            let params = st.params.clone();
            let name = f.name.clone();
            let floc = f.location.clone();
            let trace: super::TraceFn = Arc::new(move |asg: &Assignment| {
                let show = |k: &str| match asg.get(k) {
                    Some(Value::Int(i)) => i.to_string(),
                    Some(v) => format!("{v:?}"),
                    None => "?".into(),
                };
                let mut steps = vec![CounterexampleStep::new(format!(
                    "initial state: {}",
                    initial.iter().map(|(r, (n, fld))| format!("{r}.{fld} = {}", show(n))).collect::<Vec<_>>().join(", ")
                ))];
                steps.push(
                    CounterexampleStep::new(format!(
                        "call {name}({})",
                        params.iter().map(|q| if asg.contains_key(q) { format!("{q}={}", show(q)) } else { q.clone() }).collect::<Vec<_>>().join(", ")
                    ))
                    .at(Some(floc.clone())),
                );
                for (_, t, l) in &guards {
                    steps.push(CounterexampleStep::new(format!("guard {t} passes")).at(Some(l.clone())));
                }
                for (t, l) in &updates {
                    steps.push(CounterexampleStep::new(t.clone()).at(Some(l.clone())));
                }
                steps.push(CounterexampleStep::new(match kind {
                    LedgerProperty::Conservation => "total balance changed: money created or destroyed",
                    LedgerProperty::NonNegative => "a balance became negative",
                }));
                steps
            });
            out.push(Extraction {
                property_id: p.id().to_owned(),
                target,
                location: Some(f.location.clone()),
                obligation: Some(ob),
                status: None,
                reason: None,
                assumptions,
                spec_source: p.source,
                trace: Some(trace),
                replay,
                model_summary: summary,
                files: vec![f.location.file.clone()],
            });
        }
    }
    out
}
