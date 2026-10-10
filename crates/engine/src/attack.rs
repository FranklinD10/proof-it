//! The attack engine works on the REAL implementation:
//!  1. Replay: every model counterexample is executed against the code. A
//!     reproduced violation upgrades the evidence from "in the model" to
//!     "observed in the implementation".
//!  2. Property-directed adversarial inputs: values the integer/enum model
//!     cannot represent (NaN, Infinity, fractions, numeric strings, aliased
//!     accounts, junk state values). A violation found here means the code
//!     breaks the property even where the theorem about the model holds —
//!     a model gap, reported as such.

use crate::exec::{Executor, Outcome, as_number};
use proof_it_core::rng::Rng;
use proof_it_core::store::{Artifact, RunStore};
use proof_it_core::types::*;
use proof_it_model::eval::Value;
use proof_it_model::extract::{EdgeReplay, Extraction, LedgerProperty, ReplaySpec};
use proof_it_model::formal::key;
use serde_json::{Value as J, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct AttackOutput {
    pub findings: Vec<Finding>,
    pub stage: StageRun,
    pub replays: usize,
    pub reproduced: usize,
    pub cases: usize,
}

type Check = Box<dyn Fn(&Outcome) -> Option<String>>;
type Judge = Box<dyn Fn(&Outcome) -> (bool, String)>;
/// (module, function, arguments, judge) for replaying one counterexample.
type ReplayPlan = (String, String, Vec<J>, Judge);

struct Case {
    function: String,
    args: Vec<J>,
    why: String,
    check: Check,
}

fn nan() -> J {
    json!({ "$num": "NaN" })
}
fn inf(neg: bool) -> J {
    json!({ "$num": if neg { "-Infinity" } else { "Infinity" } })
}

fn show(v: &J) -> String {
    match v.get("$num").and_then(J::as_str) {
        Some(s) => s.to_owned(),
        None if v.get("$alias").is_some() => format!("<same object as arg {}>", v["$alias"]),
        None => v.to_string(),
    }
}

fn value_json(v: Option<&Value>) -> J {
    match v {
        Some(Value::Int(i)) => json!(i),
        Some(Value::Bool(b)) => json!(b),
        Some(Value::Sym(s)) => json!(s),
        None => J::Null,
    }
}

fn edge_for<'e>(edges: &'e [EdgeReplay], s: &str, t: &str) -> Option<&'e EdgeReplay> {
    edges.iter().find(|e| {
        e.from.as_ref().is_none_or(|f| f.iter().any(|x| x == s)) && (e.value_param.is_some() || e.to.as_ref().is_some_and(|to| to.iter().any(|x| x == t)))
    })
}

fn transition_args(e: &EdgeReplay, s: &str, t: Option<&J>) -> Vec<J> {
    let n = e.param_values.iter().map(|(i, _)| *i).chain([e.receiver_param, e.value_param.unwrap_or(0)]).max().unwrap_or(0) + 1;
    let mut args = vec![J::Null; n];
    for (i, v) in &e.param_values {
        args[*i] = v.clone();
    }
    args[e.receiver_param] = json!({ &e.field: s });
    if let (Some(vp), Some(t)) = (e.value_param, t) {
        args[vp] = t.clone();
    }
    args
}

fn after_field(o: &Outcome, e: &EdgeReplay) -> J {
    o.args.get(e.receiver_param).and_then(|a| a.get(&e.field)).cloned().unwrap_or(J::Null)
}

fn ledger_args(params: &[String], receivers: &[proof_it_model::extract::ReceiverReplay], balances: &[J], nums: &[J], alias: bool) -> Vec<J> {
    let mut args = Vec::new();
    let (mut bi, mut ni) = (0usize, 0usize);
    let mut first_recv: Option<usize> = None;
    for i in 0..params.len() {
        if let Some(r) = receivers.iter().find(|r| r.param == i) {
            if alias && first_recv.is_some() {
                args.push(json!({ "$alias": first_recv }));
            } else {
                args.push(json!({ &r.field: balances.get(bi % balances.len().max(1)).cloned().unwrap_or(json!(0)) }));
                bi += 1;
                first_recv.get_or_insert(i);
            }
        } else {
            args.push(nums.get(ni % nums.len().max(1)).cloned().unwrap_or(J::Null));
            ni += 1;
        }
    }
    args
}

fn ledger_check(receivers: Vec<proof_it_model::extract::ReceiverReplay>, property: LedgerProperty, initial: f64, alias: bool) -> Check {
    Box::new(move |o: &Outcome| {
        if o.threw {
            return None;
        }
        let finals: Vec<J> = receivers.iter().map(|r| o.args.get(r.param).and_then(|a| a.get(&r.field)).cloned().unwrap_or(J::Null)).collect();
        let uniq: Vec<J> = if alias { finals.into_iter().take(1).collect() } else { finals };
        match property {
            LedgerProperty::NonNegative => {
                let bad = uniq.iter().any(|x| !as_number(x).is_some_and(|n| n >= 0.0));
                bad.then(|| format!("balance(s) after the call: {} (not a non-negative number)", uniq.iter().map(show).collect::<Vec<_>>().join(", ")))
            }
            LedgerProperty::Conservation => {
                let sum: f64 = uniq.iter().map(|x| as_number(x).unwrap_or(f64::NAN)).sum();
                #[allow(clippy::float_cmp)]
                let same = sum == initial;
                (!same).then(|| format!("total balance changed from {initial} to {sum} (balances {})", uniq.iter().map(show).collect::<Vec<_>>().join(", ")))
            }
        }
    })
}

fn adversarial_numbers() -> Vec<(J, &'static str)> {
    vec![
        (json!(0), "integer boundary amounts"),
        (json!(-1), "negative amounts"),
        (json!(1), "integer boundary amounts"),
        (json!(0.1), "fractional amounts (floating point)"),
        (json!(0.5), "fractional amounts (floating point)"),
        (json!(-0.5), "fractional amounts (floating point)"),
        (nan(), "NaN amounts"),
        (inf(false), "infinite amounts"),
        (inf(true), "infinite amounts"),
        (json!(9_007_199_254_740_991_i64), "amounts at the safe-integer limit"),
        (json!(1e308), "amounts beyond safe-integer precision"),
        (json!("5"), "numeric strings"),
        (json!("1e3"), "numeric strings"),
        (json!(""), "empty strings"),
        (J::Null, "null amounts"),
    ]
}

fn generate(ex: &Extraction, rng: &mut Rng, iterations: usize) -> Vec<Case> {
    let Some(rp) = &ex.replay else { return vec![] };
    match rp {
        ReplaySpec::Ledger { function, params, receivers, property, .. } => {
            let nums_idx: Vec<usize> = (0..params.len()).filter(|i| !receivers.iter().any(|r| r.param == *i)).collect();
            let balances = [json!(0), json!(1), json!(5), json!(100)];
            let initial_of = |bal: &[J], alias: bool| -> f64 {
                if alias { as_number(&bal[0]).unwrap_or(0.0) } else { (0..receivers.len()).map(|k| as_number(&bal[k % bal.len()]).unwrap_or(0.0)).sum() }
            };
            let mut out = Vec::new();
            for (n, why) in adversarial_numbers() {
                let nums: Vec<J> = nums_idx.iter().map(|_| n.clone()).collect();
                out.push(Case {
                    function: function.clone(),
                    args: ledger_args(params, receivers, &balances, &nums, false),
                    why: why.into(),
                    check: ledger_check(receivers.clone(), *property, initial_of(&balances, false), false),
                });
            }
            if receivers.len() >= 2 {
                let nums: Vec<J> = nums_idx.iter().map(|_| json!(3)).collect();
                let bal = [json!(5)];
                out.push(Case {
                    function: function.clone(),
                    args: ledger_args(params, receivers, &bal, &nums, true),
                    why: "source and destination being the same account (aliasing)".into(),
                    check: ledger_check(receivers.clone(), *property, initial_of(&bal, true), true),
                });
            }
            let pool = [0, 1, 2, 5, 10, 100, 1000];
            while out.len() < iterations.min(200) {
                let bal: Vec<J> = receivers.iter().map(|_| json!(*rng.pick(&pool).unwrap_or(&0))).collect();
                let all = adversarial_numbers();
                let nums: Vec<J> =
                    nums_idx.iter().map(|_| if rng.below(3) == 0 { json!(rng.range_i64(-10, 1000)) } else { all[rng.below(all.len())].0.clone() }).collect();
                let init = initial_of(&bal, false);
                out.push(Case {
                    function: function.clone(),
                    args: ledger_args(params, receivers, &bal, &nums, false),
                    why: "random boundary values".into(),
                    check: ledger_check(receivers.clone(), *property, init, false),
                });
            }
            out
        }
        ReplaySpec::StateTransition { edges, .. } => {
            let Some(ob) = &ex.obligation else {
                return vec![];
            };
            let members: Vec<String> = ob.enums.first().map(|e| e.members.clone()).unwrap_or_default();
            // Terminal (STATE-001: hypothesis 2 is `s = T`) or forbidden pair (STATE-002).
            let terminal = ob.hypotheses.get(1).and_then(|h| match &h.expr {
                proof_it_model::ir::Expr::Cmp { b, .. } => match &**b {
                    proof_it_model::ir::Expr::EnumLit { member, .. } => Some(member.clone()),
                    _ => None,
                },
                _ => None,
            });
            let forbidden: Option<(String, String)> =
                ex.target.rsplit_once(':').and_then(|(_, pair)| pair.split_once("->")).map(|(a, b)| (a.to_owned(), b.to_owned()));
            let sources: Vec<String> = match (&terminal, &forbidden) {
                (Some(t), _) => vec![t.clone()],
                (None, Some((a, _))) => vec![a.clone()],
                _ => members.clone(),
            };
            let junk = [json!(""), json!("__proto__"), json!("constructor"), J::Null, json!("active"), json!("RESOLVED "), json!(0)];
            let mut out = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for e in edges {
                if !seen.insert(e.function.clone()) {
                    continue;
                }
                for s in &sources {
                    let values: Vec<(Option<J>, bool)> = if e.value_param.is_some() {
                        members.iter().map(|m| (Some(json!(m)), true)).chain(junk.iter().map(|j| (Some(j.clone()), false))).collect()
                    } else {
                        vec![(None, true)]
                    };
                    for (t, valid) in values {
                        let ec = e.clone();
                        let s2 = s.clone();
                        let terminal2 = terminal.clone();
                        let forbidden2 = forbidden.clone();
                        out.push(Case {
                            function: e.function.clone(),
                            args: transition_args(e, s, t.as_ref()),
                            why: if valid { "valid state values".into() } else { "values outside the declared state type".into() },
                            check: Box::new(move |o: &Outcome| {
                                if o.threw {
                                    return None;
                                }
                                let after = after_field(o, &ec);
                                if let Some(term) = &terminal2
                                    && after != json!(term)
                                {
                                    return Some(format!("{} changed from terminal {term} to {}", ec.field, show(&after)));
                                }
                                if let Some((a, b)) = &forbidden2
                                    && &s2 == a
                                    && after == json!(b)
                                {
                                    return Some(format!("{} changed {a} → {b} (declared forbidden)", ec.field));
                                }
                                None
                            }),
                        });
                    }
                }
            }
            out
        }
    }
}

/// Describe the input class of the arguments that broke the property.
fn classify(args: &[J], fallback: &str) -> String {
    let mut classes = Vec::new();
    for a in args {
        let c = match a {
            J::String(s) if s.is_empty() => "empty strings",
            J::String(s) if s.trim().parse::<f64>().is_ok() => "numeric strings (JavaScript coerces them in comparisons but concatenates them with +)",
            J::String(_) => "non-numeric strings",
            J::Null => "null values",
            J::Number(n) if n.as_f64().is_some_and(|x| x.fract() != 0.0) => "fractional numbers (floating point)",
            J::Number(n) if n.as_f64().is_some_and(|x| x.abs() > 9.0e15) => "numbers beyond safe-integer precision",
            J::Number(n) if n.as_f64().is_some_and(|x| x < 0.0) => "negative numbers",
            J::Object(o) if o.contains_key("$num") => match o.get("$num").and_then(J::as_str) {
                Some("NaN") => "NaN",
                _ => "infinite numbers",
            },
            J::Object(o) if o.contains_key("$alias") => "the same object passed twice (aliasing)",
            _ => continue,
        };
        if !classes.contains(&c) {
            classes.push(c);
        }
    }
    if classes.is_empty() { fallback.to_owned() } else { classes.join(", ") }
}

pub fn run(
    results: &mut [PropertyResult],
    extractions: &HashMap<String, Extraction>,
    exec: &Executor,
    store: &RunStore,
    seed: u64,
    iterations: usize,
) -> AttackOutput {
    let started = Instant::now();
    let mut rng = Rng::new(seed);
    let (mut findings, mut replays, mut reproduced, mut cases) = (Vec::new(), 0usize, 0usize, 0usize);
    let timeout = Duration::from_secs(30);
    for r in results.iter_mut() {
        let Some(ex) = extractions.get(&key(&r.property_id, &r.target)) else {
            continue;
        };
        let Some(rp) = &ex.replay else { continue };

        // 1. Replay the model counterexample.
        if r.status() == ProofStatus::Violated
            && let Some(cx) = r.counterexample.as_mut()
        {
            let asg: proof_it_model::eval::Assignment =
                cx.assignment.iter().filter_map(|(k, v)| serde_json::from_value(v.clone()).ok().map(|x| (k.clone(), x))).collect();
            let plan: Option<ReplayPlan> = match rp {
                ReplaySpec::StateTransition { module, edges, .. } => {
                    let s = match asg.get("s") {
                        Some(Value::Sym(x)) => x.clone(),
                        _ => String::new(),
                    };
                    let t = match asg.get("t") {
                        Some(Value::Sym(x)) => x.clone(),
                        _ => String::new(),
                    };
                    edge_for(edges, &s, &t).map(|e| {
                        let ec = e.clone();
                        let (s2, t2) = (s.clone(), t.clone());
                        (
                            module.clone(),
                            e.function.clone(),
                            transition_args(e, &s, Some(&json!(t))),
                            Box::new(move |o: &Outcome| {
                                if o.threw {
                                    return (false, format!("call threw: {}", o.error.clone().unwrap_or_default()));
                                }
                                let after = after_field(o, &ec);
                                (after == json!(t2) && after != json!(s2), format!("{} after call: {}", ec.field, show(&after)))
                            }) as Judge,
                        )
                    })
                }
                ReplaySpec::Ledger { module, function, params, receivers, property } => {
                    let args: Vec<J> = (0..params.len())
                        .map(|i| match receivers.iter().find(|x| x.param == i) {
                            Some(rr) => json!({ &rr.field: value_json(asg.get(&rr.initial_var)) }),
                            None => value_json(asg.get(&params[i])),
                        })
                        .collect();
                    let initial: f64 = receivers
                        .iter()
                        .map(|x| match asg.get(&x.initial_var) {
                            Some(Value::Int(i)) => *i as f64,
                            _ => 0.0,
                        })
                        .sum();
                    let check = ledger_check(receivers.clone(), *property, initial, false);
                    Some((
                        module.clone(),
                        function.clone(),
                        args,
                        Box::new(move |o: &Outcome| match check(o) {
                            Some(msg) => (true, msg),
                            None => (
                                false,
                                if o.threw { format!("call threw: {}", o.error.clone().unwrap_or_default()) } else { "property held for this input".into() },
                            ),
                        }) as Judge,
                    ))
                }
            };
            if let Some((module, function, args, judge)) = plan {
                replays += 1;
                let b = exec.call(&module, &function, std::slice::from_ref(&args), timeout);
                let shown = args.iter().map(show).collect::<Vec<_>>().join(", ");
                match (b.ok, b.outcomes.first()) {
                    (true, Some(o)) => {
                        let (rep, observed) = judge(o);
                        cx.replay = Some(ReplayResult {
                            attempted: true,
                            reproduced: Some(rep),
                            observed: Some(observed.clone()),
                            reason: if rep {
                                "violation reproduced against the implementation".into()
                            } else {
                                "implementation did not exhibit the violation".into()
                            },
                        });
                        if rep {
                            reproduced += 1;
                            r.evidence.push(Evidence::new(
                                EvidenceKind::ReplayedAgainstCode,
                                format!(
                                    "executed {function}({shown}) {}: {observed}",
                                    if b.sandboxed { "in a sandbox" } else { "WITHOUT a sandbox (bwrap missing)" }
                                ),
                            ));
                        } else {
                            r.evidence.push(Evidence::new(
                                EvidenceKind::ReplayedAgainstCode,
                                format!("replay did NOT reproduce: {observed}. The model may over-approximate the code."),
                            ));
                        }
                    }
                    _ => {
                        cx.replay =
                            Some(ReplayResult { attempted: true, reproduced: None, observed: None, reason: b.error.unwrap_or_else(|| "no outcome".into()) })
                    }
                }
            }
        }

        // 2. Property-directed adversarial inputs.
        let module = match rp {
            ReplaySpec::StateTransition { module, .. } | ReplaySpec::Ledger { module, .. } => module.clone(),
        };
        let generated = generate(ex, &mut rng, iterations);
        if generated.is_empty() {
            continue;
        }
        let mut by_fn: HashMap<String, Vec<&Case>> = HashMap::new();
        for c in &generated {
            by_fn.entry(c.function.clone()).or_default().push(c);
        }
        let mut executed: Vec<(&Case, Outcome)> = Vec::new();
        let mut failure: Option<String> = None;
        for (f, cs) in &by_fn {
            let b = exec.call(&module, f, &cs.iter().map(|c| c.args.clone()).collect::<Vec<_>>(), timeout);
            if b.ok {
                executed.extend(cs.iter().copied().zip(b.outcomes));
            } else {
                failure = b.error;
            }
        }
        cases += executed.len();
        if executed.is_empty() {
            r.evidence.push(Evidence::new(EvidenceKind::Assumption, format!("adversarial testing could not run: {}", failure.unwrap_or_default())));
            continue;
        }
        let mut violations: Vec<(&Case, String)> = executed.iter().filter_map(|(c, o)| (c.check)(o).map(|m| (*c, m))).collect();
        if violations.is_empty() {
            r.evidence.push(Evidence::new(
                EvidenceKind::BoundedSearch,
                format!("{} adversarial input(s) executed against the implementation without violating the property (seed {seed})", executed.len()),
            ));
            continue;
        }
        violations.sort_by_key(|(c, _)| serde_json::to_string(&c.args).map(|s| s.len()).unwrap_or(usize::MAX));
        let (worst, observed) = &violations[0];
        let why = classify(&worst.args, &worst.why);
        let shown = worst.args.iter().map(show).collect::<Vec<_>>().join(", ");
        let was_proven = r.status() == ProofStatus::Proven;
        let cx = Counterexample {
            property_id: r.property_id.clone(),
            target: r.target.clone(),
            assignment: [("args".to_owned(), J::Array(worst.args.clone()))].into_iter().collect(),
            steps: vec![
                CounterexampleStep::new(format!("call {}({shown})", worst.function)).at(r.location.clone()),
                CounterexampleStep::new(format!("observed: {observed}")),
                CounterexampleStep::new(format!("input class not represented in the model: {why}")),
            ],
            violated_invariant: r.property_name.clone(),
            seed,
            lean_certificate: None,
            replay: Some(ReplayResult {
                attempted: true,
                reproduced: Some(true),
                observed: Some(observed.clone()),
                reason: "found by property-directed adversarial testing".into(),
            }),
        };
        let file = json!({ "format": proof_it_model::formal::CX_FORMAT, "proof_it_version": proof_it_core::VERSION, "counterexample": cx, "replay": rp, "attack": { "function": worst.function, "args": worst.args } });
        let rel = store
            .write_artifact(
                Artifact::Counterexamples,
                &format!("{}__{}__attack.json", r.property_id, r.target),
                &serde_json::to_string_pretty(&file).unwrap_or_default(),
            )
            .map(|(_, rel)| rel)
            .ok();
        if r.status() != ProofStatus::Violated {
            let note = if was_proven {
                format!(" The Lean theorem still holds for the model; the violation comes from behaviour the model abstracts away ({why}).")
            } else {
                String::new()
            };
            r.set_status(ProofStatus::Violated, format!("Executed counterexample: {}({shown}) → {observed}.{note}", worst.function));
            r.counterexample = Some(cx);
        }
        let mut ev = Evidence::new(
            EvidenceKind::ReplayedAgainstCode,
            format!("{}/{} adversarial input(s) violate the property; minimal: {}({shown})", violations.len(), executed.len(), worst.function),
        );
        if let Some(rel) = &rel {
            ev = ev.with_artifact(rel.clone());
        }
        r.evidence.push(ev.clone());
        let location = r.location.clone().unwrap_or_else(|| SourceLocation::new(module.clone(), 1));
        findings.push(Finding {
            id: fingerprint(&format!("ATTACK-{}", r.property_id), Some(&location), &r.target),
            rule_id: format!("ATTACK-{}", r.property_id),
            property_id: Some(r.property_id.clone()),
            title: format!("{}: violated by executed input", r.property_name),
            source: FindingSource::Attack,
            severity: r.severity,
            confidence: Confidence::High,
            location: Some(location),
            description: format!(
                "{}({shown}) → {observed}.{}",
                worst.function,
                if was_proven { format!(" The model-level proof does not cover this input class: {why}.") } else { String::new() }
            ),
            evidence: vec![ev],
            recommendation: Some(if was_proven {
                format!("Validate inputs so they stay inside the modeled domain ({why}), e.g. Number.isSafeInteger(amount) && amount > 0.")
            } else {
                r.recommendation.clone().unwrap_or_default()
            }),
            cwe: vec![],
            suppressed: None,
            baseline: None,
        });
    }
    let detail = format!(
        "{replays} replay(s), {reproduced} reproduced, {cases} adversarial case(s){}",
        if exec.sandboxed { ", sandboxed" } else { ", NOT sandboxed (bwrap missing)" }
    );
    AttackOutput {
        findings,
        stage: StageRun::new("attack", StageStatus::Ran, u64::try_from(started.elapsed().as_millis()).unwrap_or(0), detail),
        replays,
        reproduced,
        cases,
    }
}
