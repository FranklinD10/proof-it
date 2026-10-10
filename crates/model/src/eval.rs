//! Concrete semantics of the model IR, mirroring the Lean encoding: Int is
//! mathematical (checked i64; an overflow aborts evaluation instead of
//! wrapping, so it can never produce a spurious counterexample), Nat is
//! non-negative, enums are finite.

use crate::ir::*;
use proof_it_core::facts::CmpOp;
use proof_it_core::rng::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Sym(String),
}

pub type Assignment = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError(pub String);

pub struct Evaluator<'o> {
    defs: HashMap<&'o str, &'o Def>,
}

impl<'o> Evaluator<'o> {
    pub fn new(ob: &'o Obligation) -> Self {
        Self { defs: ob.defs.iter().map(|d| (d.name.as_str(), d)).collect() }
    }

    pub fn eval(&self, e: &Expr, env: &Assignment) -> Result<Value, EvalError> {
        let int = |x: &Expr| match self.eval(x, env)? {
            Value::Int(i) => Ok(i),
            v => Err(EvalError(format!("expected integer, got {v:?}"))),
        };
        let boolean = |x: &Expr| match self.eval(x, env)? {
            Value::Bool(b) => Ok(b),
            v => Err(EvalError(format!("expected boolean, got {v:?}"))),
        };
        Ok(match e {
            Expr::Var { name } => env.get(name).cloned().ok_or_else(|| EvalError(format!("unbound variable {name}")))?,
            Expr::Int { v } => Value::Int(*v),
            Expr::Bool { v } => Value::Bool(*v),
            Expr::EnumLit { member, .. } => Value::Sym(member.clone()),
            Expr::Not { e } => Value::Bool(!boolean(e)?),
            Expr::And { es } => {
                for x in es {
                    if !boolean(x)? {
                        return Ok(Value::Bool(false));
                    }
                }
                Value::Bool(true)
            }
            Expr::Or { es } => {
                for x in es {
                    if boolean(x)? {
                        return Ok(Value::Bool(true));
                    }
                }
                Value::Bool(false)
            }
            Expr::Cmp { op, a, b } => {
                let (va, vb) = (self.eval(a, env)?, self.eval(b, env)?);
                Value::Bool(match op {
                    CmpOp::Eq => va == vb,
                    CmpOp::Ne => va != vb,
                    _ => {
                        let (Value::Int(x), Value::Int(y)) = (va, vb) else {
                            return Err(EvalError("ordering on non-integers".into()));
                        };
                        match op {
                            CmpOp::Lt => x < y,
                            CmpOp::Le => x <= y,
                            CmpOp::Gt => x > y,
                            CmpOp::Ge => x >= y,
                            CmpOp::Eq | CmpOp::Ne => unreachable!("handled above"),
                        }
                    }
                })
            }
            Expr::Arith { op, a, b } => {
                let (x, y) = (int(a)?, int(b)?);
                let r = match op {
                    Arith::Add => x.checked_add(y),
                    Arith::Sub => x.checked_sub(y),
                    Arith::Mul => x.checked_mul(y),
                };
                Value::Int(r.ok_or_else(|| EvalError("integer overflow in model evaluation".into()))?)
            }
            Expr::Call { f, args } => {
                let d = self.defs.get(f.as_str()).ok_or_else(|| EvalError(format!("unknown def {f}")))?;
                let vals: Vec<Value> = args.iter().map(|a| self.eval(a, env)).collect::<Result<_, _>>()?;
                match &d.body {
                    DefBody::Table { rows, .. } => {
                        Value::Bool(rows.iter().any(|r| r.len() == vals.len() && r.iter().zip(&vals).all(|(m, v)| matches!(v, Value::Sym(s) if s == m))))
                    }
                    DefBody::Expr { e } => {
                        let mut local = env.clone();
                        for ((p, _), v) in d.params.iter().zip(vals) {
                            local.insert(p.clone(), v);
                        }
                        Value::Bool(boolean_of(self.eval(e, &local)?)?)
                    }
                }
            }
        })
    }

    pub fn holds(&self, e: &Expr, env: &Assignment) -> Result<bool, EvalError> {
        boolean_of(self.eval(e, env)?)
    }
}

fn boolean_of(v: Value) -> Result<bool, EvalError> {
    match v {
        Value::Bool(b) => Ok(b),
        v => Err(EvalError(format!("expected boolean, got {v:?}"))),
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub counterexample: Option<Assignment>,
    /// The whole finite domain was enumerated.
    pub exhaustive: bool,
    /// The domain covers every behaviour of the obligation (no Int variables).
    pub complete: bool,
    pub evaluated: u64,
}

fn domain(sort: &Sort, enums: &HashMap<&str, &[String]>, ints: &[i64], nat_count: usize) -> Vec<Value> {
    match sort {
        Sort::Bool => vec![Value::Bool(false), Value::Bool(true)],
        Sort::Enum { name } => enums.get(name.as_str()).map(|m| m.iter().map(|x| Value::Sym(x.clone())).collect()).unwrap_or_default(),
        // Nat variables are only compared for equality: |vars| values cover every equality pattern.
        Sort::Nat => (0..nat_count.max(2) as i64).map(Value::Int).collect(),
        Sort::Int => ints.iter().copied().map(Value::Int).collect(),
    }
}

/// Is `asg` a violation (all hypotheses true, conclusion false)? Evaluation errors are not violations.
pub fn violates(ev: &Evaluator<'_>, ob: &Obligation, asg: &Assignment) -> bool {
    for h in &ob.hypotheses {
        if ev.holds(&h.expr, asg) != Ok(true) {
            return false;
        }
    }
    ev.holds(&ob.conclusion, asg) == Ok(false)
}

/// Search for an assignment satisfying all hypotheses and falsifying the conclusion.
pub fn search(ob: &Obligation, rng: &mut Rng, budget: u64) -> SearchResult {
    let ev = Evaluator::new(ob);
    let enums: HashMap<&str, &[String]> = ob.enums.iter().map(|e| (e.name.as_str(), e.members.as_slice())).collect();
    let mut lits = Vec::new();
    for h in &ob.hypotheses {
        h.expr.int_literals(&mut lits);
    }
    ob.conclusion.int_literals(&mut lits);
    let mut ints: BTreeSet<i64> = [-2, -1, 0, 1, 2, 3, 100].into_iter().collect();
    for l in lits {
        for d in [-1, 0, 1] {
            if let Some(x) = l.checked_add(d) {
                ints.insert(x);
            }
        }
    }
    let ints: Vec<i64> = ints.into_iter().collect();
    let nat_count = ob.vars.iter().filter(|v| v.sort == Sort::Nat).count();
    let domains: Vec<Vec<Value>> = ob.vars.iter().map(|v| domain(&v.sort, &enums, &ints, nat_count)).collect();
    let has_int = ob.vars.iter().any(|v| v.sort == Sort::Int);
    let total = domains.iter().try_fold(1u64, |acc, d| acc.checked_mul(d.len().max(1) as u64));

    if let Some(total) = total.filter(|t| *t <= budget) {
        let mut asg = Assignment::new();
        let mut evaluated = 0u64;
        let mut idx = vec![0usize; domains.len()];
        if domains.iter().any(Vec::is_empty) {
            return SearchResult { counterexample: None, exhaustive: true, complete: !has_int, evaluated: 0 };
        }
        loop {
            for (i, v) in ob.vars.iter().enumerate() {
                asg.insert(v.name.clone(), domains[i][idx[i]].clone());
            }
            evaluated += 1;
            if violates(&ev, ob, &asg) {
                return SearchResult { counterexample: Some(asg), exhaustive: true, complete: !has_int, evaluated };
            }
            // odometer increment
            let mut k = 0;
            loop {
                if k == idx.len() {
                    let _ = total;
                    return SearchResult { counterexample: None, exhaustive: true, complete: !has_int, evaluated };
                }
                idx[k] += 1;
                if idx[k] < domains[k].len() {
                    break;
                }
                idx[k] = 0;
                k += 1;
            }
        }
    }
    for n in 0..budget {
        let mut asg = Assignment::new();
        for (i, v) in ob.vars.iter().enumerate() {
            if let Some(x) = rng.pick(&domains[i]) {
                asg.insert(v.name.clone(), x.clone());
            }
        }
        if violates(&ev, ob, &asg) {
            return SearchResult { counterexample: Some(asg), exhaustive: false, complete: false, evaluated: n + 1 };
        }
    }
    SearchResult { counterexample: None, exhaustive: false, complete: false, evaluated: budget }
}

/// Whether the violation at `asg` survives every value of the opaque variables.
/// Opaque variables are finite (bool/enum), so this is exact.
pub fn violation_is_robust(ob: &Obligation, asg: &Assignment) -> bool {
    let ev = Evaluator::new(ob);
    let enums: HashMap<&str, &[String]> = ob.enums.iter().map(|e| (e.name.as_str(), e.members.as_slice())).collect();
    let opaque: Vec<&ModelVar> = ob.vars.iter().filter(|v| v.opaque).collect();
    fn rec(i: usize, opaque: &[&ModelVar], cur: &mut Assignment, ev: &Evaluator<'_>, ob: &Obligation, enums: &HashMap<&str, &[String]>) -> bool {
        let Some(o) = opaque.get(i) else {
            return violates(ev, ob, cur);
        };
        let dom = domain(&o.sort, enums, &[], 0);
        dom.into_iter().all(|v| {
            cur.insert(o.name.clone(), v);
            rec(i + 1, opaque, cur, ev, ob, enums)
        })
    }
    let mut cur = asg.clone();
    rec(0, &opaque, &mut cur, &ev, ob, &enums)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ob(hyps: Vec<Expr>, concl: Expr, vars: Vec<ModelVar>) -> Obligation {
        Obligation {
            theorem: "t".into(),
            property_id: "X-001".into(),
            statement: String::new(),
            enums: vec![],
            defs: vec![],
            vars,
            hypotheses: hyps.into_iter().map(|e| Hypothesis { assumed: false, expr: e, label: String::new(), location: None }).collect(),
            conclusion: concl,
            extras: vec![],
            meaningful_if: None,
        }
    }

    #[test]
    fn finds_overdraft() {
        let o = ob(
            vec![cmp(CmpOp::Gt, var("amt"), int(0)), cmp(CmpOp::Ge, var("b"), int(0))],
            cmp(CmpOp::Ge, arith(Arith::Sub, var("b"), var("amt")), int(0)),
            vec![ModelVar::new("amt", Sort::Int, ""), ModelVar::new("b", Sort::Int, "")],
        );
        let r = search(&o, &mut Rng::new(1), 100_000);
        assert!(r.counterexample.is_some());
        assert!(r.exhaustive && !r.complete);
    }

    #[test]
    fn equality_domain_is_complete_for_nats() {
        // owner = principal → owner = principal: no counterexample, and the search is complete.
        let o = ob(vec![eq(var("o"), var("p"))], eq(var("o"), var("p")), vec![ModelVar::new("o", Sort::Nat, ""), ModelVar::new("p", Sort::Nat, "")]);
        let r = search(&o, &mut Rng::new(1), 1000);
        assert!(r.counterexample.is_none() && r.complete);
    }

    #[test]
    fn opaque_gates_make_violations_non_robust() {
        // gate → owner = principal: violated only when gate is true.
        let o = ob(
            vec![var("g")],
            eq(var("o"), var("p")),
            vec![ModelVar::new("o", Sort::Nat, ""), ModelVar::new("p", Sort::Nat, ""), ModelVar::opaque("g", Sort::Bool, "")],
        );
        let r = search(&o, &mut Rng::new(1), 1000);
        let asg = r.counterexample.expect("cex");
        assert!(!violation_is_robust(&o, &asg));
    }

    #[test]
    fn overflow_is_not_a_counterexample() {
        let o = ob(vec![], cmp(CmpOp::Ge, arith(Arith::Add, var("x"), int(i64::MAX)), int(0)), vec![ModelVar::new("x", Sort::Int, "")]);
        let ev = Evaluator::new(&o);
        let asg: Assignment = [("x".to_owned(), Value::Int(5))].into_iter().collect();
        assert!(!violates(&ev, &o, &asg));
    }
}
