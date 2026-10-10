//! The formal engine.
//!
//! For each property with a formal model:
//!   extract obligations → emit Lean → kernel check + axiom audit → non-vacuity
//!   witness; on failure, an (untrusted) agent proof hint may supply a different
//!   tactic for the SAME generated statement; otherwise bounded counterexample
//!   search → robustness w.r.t. opaque conditions → Lean certificate.
//!
//! Status rules (the core of Proof-It's honesty):
//!   PROVEN   only via `PropertyResult::prove`, which needs a KernelAcceptance
//!            (foundation axioms only) and a non-vacuous theorem;
//!   VIOLATED only if a concrete assignment violates the obligation for EVERY
//!            value of every opaque condition;
//!   UNPROVEN otherwise, with the reason.

use crate::eval::{Assignment, search, violation_is_robust};
use crate::extract::{ExtractContext, Extraction, ReplaySpec, run_extractor};
use crate::ir::{Expr, Hypothesis, Obligation};
use crate::lean::emit::{emit_certificate, emit_obligation, ident};
use crate::lean::runner::{LeanCheck, check_file, toolchain};
use proof_it_core::facts::ProgramFacts;
use proof_it_core::paths::safe_file_name;
use proof_it_core::property::Property;
use proof_it_core::rng::Rng;
use proof_it_core::store::{Artifact, ProofCache, RunStore};
use proof_it_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct FormalOptions {
    pub seed: u64,
    pub search_budget: u64,
    pub timeout: Duration,
    pub parallel: bool,
    pub max_proofs: usize,
    /// `.proof-it/proof-hints/` — agent-supplied tactic scripts (untrusted).
    pub hints_dir: Option<PathBuf>,
}

pub struct FormalOutput {
    pub results: Vec<PropertyResult>,
    pub extractions: HashMap<String, Extraction>,
    pub stage: StageRun,
}

pub fn key(property_id: &str, target: &str) -> String {
    format!("{property_id}::{target}")
}

fn translation_assumption() -> String {
    format!("The translation from source code to the model is performed by Proof-It {}'s extractor and is not itself verified.", proof_it_core::VERSION)
}

/// Applicability of a non-formal property from its signal regexes.
pub fn applies(p: &Property, facts: &ProgramFacts) -> bool {
    p.signals.is_empty() || facts.texts.iter().any(|(_, t)| p.signal_matches(t))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CounterexampleFile {
    pub format: String,
    pub proof_it_version: String,
    #[serde(flatten)]
    pub counterexample: Counterexample,
    pub obligation: Option<Obligation>,
    pub replay: Option<ReplaySpec>,
}

pub const CX_FORMAT: &str = "proof-it/counterexample@1";

pub fn run(props: &[&Property], ctx: &ExtractContext<'_>, store: &RunStore, cache: &ProofCache, opts: &FormalOptions) -> FormalOutput {
    let started = Instant::now();
    let mut results = Vec::new();
    let mut extractions = HashMap::new();
    let mut pending: Vec<(&Property, Extraction)> = Vec::new();
    for p in props {
        if p.spec.formal.is_none() {
            let a = applies(p, ctx.facts);
            let reason = if a {
                let det = if p.spec.detectors.is_empty() {
                    String::new()
                } else {
                    format!(" Non-formal evidence comes from detectors: {}.", p.spec.detectors.join(", "))
                };
                format!("No formal model exists for this property yet.{det}")
            } else {
                "No code matched this property's applicability signals.".to_owned()
            };
            let mut r = PropertyResult::new(
                p.id(),
                p.name(),
                "repository",
                if a { ProofStatus::NotModeled } else { ProofStatus::NotApplicable },
                p.severity,
                p.source,
                reason,
            );
            r.level = if a { FormalizationLevel::MATCHED } else { FormalizationLevel::STATIC };
            results.push(r);
            continue;
        }
        let exs = run_extractor(p, ctx);
        if exs.is_empty() {
            results.push(PropertyResult::new(
                p.id(),
                p.name(),
                "repository",
                ProofStatus::NotApplicable,
                p.severity,
                p.source,
                "no code matched this property's extractor",
            ));
            continue;
        }
        for ex in exs.into_iter().take(opts.max_proofs) {
            if ex.obligation.is_none() {
                let mut r = PropertyResult::new(
                    p.id(),
                    p.name(),
                    &ex.target,
                    ex.status.unwrap_or(ProofStatus::NotModeled),
                    p.severity,
                    ex.spec_source,
                    ex.reason.clone().unwrap_or_default(),
                );
                r.location.clone_from(&ex.location);
                r.assumptions.clone_from(&ex.assumptions);
                extractions.insert(key(p.id(), &ex.target), ex);
                results.push(r);
            } else {
                pending.push((p, ex));
            }
        }
    }
    let n = pending.len();
    let workers = if opts.parallel { std::thread::available_parallelism().map_or(2, |x| x.get()).clamp(1, 8) } else { 1 };
    let next = Mutex::new(0usize);
    let done: Mutex<Vec<PropertyResult>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..workers.min(n.max(1)) {
            s.spawn(|| {
                loop {
                    let i = {
                        let Ok(mut g) = next.lock() else { return };
                        let i = *g;
                        *g += 1;
                        i
                    };
                    let Some((p, ex)) = pending.get(i) else { return };
                    // Isolate each obligation: an internal failure becomes an ERROR result, never a crashed run.
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_one(p, ex, store, cache, opts))).unwrap_or_else(|e| {
                        let msg = e
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                            .unwrap_or_else(|| "unknown panic".into());
                        let mut r = PropertyResult::new(
                            p.id(),
                            p.name(),
                            &ex.target,
                            ProofStatus::Error,
                            p.severity,
                            ex.spec_source,
                            format!("internal error in Proof-It while verifying this target: {msg}. Please report this bug."),
                        );
                        r.location.clone_from(&ex.location);
                        r
                    });
                    if let Ok(mut d) = done.lock() {
                        d.push(r);
                    }
                }
            });
        }
    });
    results.extend(done.into_inner().unwrap_or_default());
    for (p, ex) in pending {
        extractions.insert(key(p.id(), &ex.target), ex);
    }
    results.sort_by(|a, b| a.property_id.cmp(&b.property_id).then_with(|| a.target.cmp(&b.target)));
    let mut stage = StageRun::new("formal", StageStatus::Ran, u64::try_from(started.elapsed().as_millis()).unwrap_or(0), format!("{n} obligation(s)"));
    match toolchain() {
        Some(tc) => stage.version = Some(tc.version.clone()),
        None => stage.detail = Some(format!("{n} obligation(s); Lean not found — nothing can be PROVEN")),
    }
    FormalOutput { results, extractions, stage }
}

fn check_cached(abs: &std::path::Path, source: &str, theorems: &[String], cache: &ProofCache, timeout: Duration) -> LeanCheck {
    let tc = toolchain().map(|t| t.version.clone()).unwrap_or_default();
    let k = ProofCache::key(&tc, source);
    if let Some(mut c) = cache.get::<LeanCheck>(&k).filter(|c| c.accepted) {
        c.reason.push_str(" (cached)");
        return c;
    }
    let c = check_file(abs, theorems, timeout);
    if c.accepted {
        cache.put(&k, &c);
    }
    c
}

fn hint_for(opts: &FormalOptions, theorem: &str) -> Option<String> {
    let dir = opts.hints_dir.as_ref()?;
    let p = dir.join(format!("{}.lean", safe_file_name(theorem, 120)));
    let meta = std::fs::symlink_metadata(&p).ok()?;
    if meta.file_type().is_symlink() || meta.len() > 32 * 1024 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

pub fn verify_one(p: &Property, ex: &Extraction, store: &RunStore, cache: &ProofCache, opts: &FormalOptions) -> PropertyResult {
    let Some(ob) = &ex.obligation else {
        return PropertyResult::new(p.id(), p.name(), &ex.target, ProofStatus::Error, p.severity, ex.spec_source, "internal: verify_one without obligation");
    };
    let ns = format!("ProofIt.Generated.{}", ident(p.id()));
    let mut header = vec![
        format!("Generated by Proof-It {}. Do not edit: regenerate with `proof-it verify`.", proof_it_core::VERSION),
        format!("Property: {} — {}", p.id(), p.name()),
        format!("Target: {}", ex.target),
        format!("Specification source: {}", ex.spec_source.label()),
    ];
    header.extend(ex.model_summary.iter().cloned());
    let base = format!("{}__{}", p.id(), ex.target);
    let mut r = PropertyResult::new(p.id(), p.name(), &ex.target, ProofStatus::Unproven, p.severity, ex.spec_source, "");
    r.location.clone_from(&ex.location);
    r.assumptions = ex.assumptions.iter().cloned().chain(std::iter::once(translation_assumption())).collect();
    r.recommendation = Some(p.spec.recommendation.clone()).filter(|s| !s.is_empty());
    r.level = FormalizationLevel::MODELED;
    let opaque: Vec<String> = ob.vars.iter().filter(|v| v.opaque).map(|v| v.meaning.clone()).collect();
    r.quality = Some(ProofQuality {
        kernel_checked: false,
        axioms: vec![],
        extra_axioms: vec![],
        unverified_translation: true,
        opaque_predicates: opaque.clone(),
        non_vacuity: NonVacuity::Unknown,
        proof_from_hint: false,
    });

    let emitted = emit_obligation(ob, &header, &ns, None);
    r.theorem = emitted.theorems.first().cloned();
    let Ok((abs, rel)) = store.write_artifact(Artifact::Proofs, &format!("{base}.lean"), &emitted.source) else {
        r.set_status(ProofStatus::Error, "could not write proof file");
        return r;
    };
    let have_lean = toolchain().is_some();
    let mut check = if have_lean { Some(check_cached(&abs, &emitted.source, &emitted.theorems, cache, opts.timeout)) } else { None };
    let mut proof_rel = rel.clone();
    let mut from_hint = false;
    // Untrusted agent hint: a different tactic for the SAME generated statement.
    if have_lean
        && !check.as_ref().is_some_and(|c| c.accepted)
        && let Some(hint) = hint_for(opts, &ident(&ob.theorem))
    {
        let hinted = emit_obligation(
            ob,
            &[header.clone(), vec!["Proof script supplied by an UNTRUSTED proof hint; statement generated by Proof-It.".into()]].concat(),
            &ns,
            Some(&hint),
        );
        if let Ok((habs, hrel)) = store.write_artifact(Artifact::Proofs, &format!("{base}.hint.lean"), &hinted.source) {
            let hc = check_file(&habs, &hinted.theorems, opts.timeout);
            r.evidence.push(Evidence::new(EvidenceKind::Assumption, format!("agent proof hint tried: {}", hc.reason)).with_artifact(hrel.clone()));
            if hc.accepted {
                check = Some(hc);
                proof_rel = hrel;
                from_hint = true;
            }
        }
    }
    if let Some(c) = &check {
        let _ = store.write_artifact(Artifact::Proofs, &format!("{base}.log"), if c.raw_output.is_empty() { "(no output)\n" } else { &c.raw_output });
        if let Some(acc) = c.acceptance(&proof_rel) {
            r.evidence.push(
                Evidence::new(
                    EvidenceKind::KernelChecked,
                    format!("theorem {} accepted by the Lean kernel ({})", emitted.theorems[0], c.toolchain.clone().unwrap_or_default()),
                )
                .with_artifact(proof_rel.clone())
                .with_details(serde_json::json!({ "axioms": c.axioms })),
            );
            let (nv, ev) = non_vacuity(ob, &header, &ns, &base, store, opts);
            if let Some(e) = ev {
                r.evidence.push(e);
            }
            // Does the conclusion already follow from the assumptions alone?
            let by_assumption = assumption_only(ob, opts);
            if let Some(labels) = &by_assumption
                && proof_it_core::decision::classify(true, nv == NonVacuity::Vacuous, false, false, true) != ProofStatus::Proven
            {
                r.evidence.push(Evidence::new(
                    EvidenceKind::BoundedSearch,
                    "exhaustive search: the conclusion holds under the assumed hypotheses alone; the code contributes nothing",
                ));
                r.set_status(
                    ProofStatus::Unproven,
                    format!(
                        "Lean accepted the theorem, but it holds BY ASSUMPTION ONLY ({labels}). The proof establishes nothing about the code: it restates what Proof-It assumed. Show the check in code (or in a guard whose code is in the repository) to make it provable."
                    ),
                );
                return r;
            }
            // Status per the Lean-specified classifier (proof_it_core::decision::classify).
            if proof_it_core::decision::classify(true, nv == NonVacuity::Vacuous, false, false, false) != ProofStatus::Proven {
                r.set_status(ProofStatus::Unproven, format!("Lean accepted the theorem, but it is VACUOUS: no state satisfies {}. The situation the property talks about cannot occur in the model, so the proof establishes nothing.", ob.meaningful_if.as_ref().unwrap_or(&ob.hypotheses).iter().map(|h| h.label.as_str()).collect::<Vec<_>>().join("; ")));
                if let Some(q) = r.quality.as_mut() {
                    q.non_vacuity = nv;
                }
                return r;
            }
            if r.prove(&acc, nv).is_ok() {
                if let Some(q) = r.quality.as_mut() {
                    q.proof_from_hint = from_hint;
                    q.opaque_predicates.clone_from(&opaque);
                }
                let axioms = if acc.axioms.is_empty() { "none".to_owned() } else { acc.axioms.join(", ") };
                r.reason = format!(
                    "Lean kernel accepted {} (axioms: {axioms}; non-vacuity: {}){}.",
                    emitted.theorems.join(" and "),
                    serde_json::to_value(nv).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
                    if from_hint { "; proof script from an untrusted hint, statement generated by Proof-It" } else { "" }
                );
                return r;
            }
        }
        if let Some(q) = r.quality.as_mut() {
            q.extra_axioms.clone_from(&c.extra_axioms);
        }
    }

    // No proof: search for a concrete counterexample in the model.
    let mut rng = Rng::new(opts.seed);
    let s = search(ob, &mut rng, opts.search_budget);
    if let Some(asg) = s.counterexample {
        let steps = ex.trace.as_ref().map(|t| t(&asg)).unwrap_or_default();
        let assignment = asg.iter().map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or_default())).collect();
        let mut cx = Counterexample {
            property_id: p.id().to_owned(),
            target: ex.target.clone(),
            assignment,
            steps,
            violated_invariant: ob.statement.clone(),
            seed: opts.seed,
            lean_certificate: None,
            replay: None,
        };
        if proof_it_core::decision::classify(false, false, true, violation_is_robust(ob, &asg), false) != ProofStatus::Violated {
            r.set_status(
                ProofStatus::Unproven,
                format!(
                    "A violation exists only if an unanalysed condition holds ({}). Proof-It cannot see what that condition checks.{}",
                    opaque.join("; "),
                    check.as_ref().map(|c| format!(" Lean: {}.", c.reason)).unwrap_or_default()
                ),
            );
            r.evidence.push(
                Evidence::new(EvidenceKind::BoundedSearch, "candidate violation depends on opaque condition(s); not reported as VIOLATED")
                    .with_details(serde_json::to_value(&asg).unwrap_or_default()),
            );
            return r;
        }
        r.evidence.push(Evidence::new(
            EvidenceKind::BoundedSearch,
            format!("{} search over {} model state(s) found a violation", if s.exhaustive { "exhaustive" } else { "randomised" }, s.evaluated),
        ));
        if have_lean {
            let cert =
                emit_certificate(ob, &asg, &[header.clone(), vec!["Counterexample certificate.".into()]].concat(), &format!("{ns}.Cex"), "_counterexample");
            if let Ok((cabs, crel)) = store.write_artifact(Artifact::Counterexamples, &format!("{base}.lean"), &cert.source) {
                let cc = check_file(&cabs, &cert.theorems, opts.timeout);
                if cc.accepted {
                    cx.lean_certificate = Some(crel.clone());
                    r.evidence.push(
                        Evidence::new(EvidenceKind::KernelCheckedCounterexample, "Lean kernel confirmed the assignment violates the property in the model")
                            .with_artifact(crel),
                    );
                } else {
                    r.evidence.push(
                        Evidence::new(EvidenceKind::BoundedSearch, format!("counterexample certificate NOT accepted by Lean: {}", cc.reason))
                            .with_artifact(crel),
                    );
                }
            }
        }
        let file = CounterexampleFile {
            format: CX_FORMAT.into(),
            proof_it_version: proof_it_core::VERSION.into(),
            counterexample: cx.clone(),
            obligation: Some(ob.clone()),
            replay: ex.replay.clone(),
        };
        if let Ok(text) = serde_json::to_string_pretty(&file)
            && let Ok((_, jrel)) = store.write_artifact(Artifact::Counterexamples, &format!("{base}.json"), &text)
        {
            r.evidence.push(Evidence::new(EvidenceKind::BoundedSearch, "counterexample saved").with_artifact(jrel));
        }
        let shown: Vec<String> =
            asg.iter().filter(|(k, _)| !k.starts_with("gate")).map(|(k, v)| format!("{k}={}", serde_json::to_string(v).unwrap_or_default())).collect();
        r.set_status(
            ProofStatus::Violated,
            format!(
                "Counterexample: {}.{}",
                shown.join(", "),
                if ex.spec_source == SpecSource::Inferred { " The specification was inferred; confirm the intended behaviour." } else { "" }
            ),
        );
        r.level = if have_lean { FormalizationLevel::LEAN } else { FormalizationLevel::MODELED };
        r.counterexample = Some(cx);
        return r;
    }
    let note = if s.exhaustive && s.complete {
        "exhaustive search over the finite model found no counterexample".to_owned()
    } else {
        format!("bounded search over {} state(s) found no counterexample", s.evaluated)
    };
    r.evidence.push(Evidence::new(EvidenceKind::BoundedSearch, note.clone()));
    let reason = match &check {
        Some(c) => format!("{}; {note}. No counterexample is not a proof.", c.reason),
        None => format!("Lean is not installed, so nothing can be proven; {note}."),
    };
    r.set_status(ProofStatus::Unproven, reason);
    r
}

/// `Some(labels)` when the conclusion holds for every state satisfying the
/// *assumed* hypotheses alone (exhaustive search over the model).
fn assumption_only(ob: &Obligation, opts: &FormalOptions) -> Option<String> {
    let assumed: Vec<Hypothesis> = ob.hypotheses.iter().filter(|h| h.assumed).cloned().collect();
    if assumed.is_empty() {
        return None;
    }
    let mut only = ob.clone();
    for v in &mut only.vars {
        v.opaque = false;
    }
    only.extras.clear();
    only.meaningful_if = None;
    only.hypotheses.clone_from(&assumed);
    let s = search(&only, &mut Rng::new(opts.seed), opts.search_budget);
    (s.counterexample.is_none() && s.exhaustive && s.complete).then(|| assumed.iter().map(|h| h.label.as_str()).collect::<Vec<_>>().join("; "))
}

fn non_vacuity(ob: &Obligation, header: &[String], ns: &str, base: &str, store: &RunStore, opts: &FormalOptions) -> (NonVacuity, Option<Evidence>) {
    // A state satisfying every hypothesis: same search with conclusion = false.
    let mut sat = ob.clone();
    for v in &mut sat.vars {
        v.opaque = false;
    }
    if let Some(m) = &ob.meaningful_if {
        sat.hypotheses.clone_from(m);
    }
    sat.extras.clear();
    sat.conclusion = Expr::Bool { v: false };
    let s = search(&sat, &mut Rng::new(opts.seed), opts.search_budget);
    let Some(w) = s.counterexample else {
        return if s.exhaustive && s.complete {
            (NonVacuity::Vacuous, Some(Evidence::new(EvidenceKind::BoundedSearch, "exhaustive search: the hypotheses are unsatisfiable (vacuous theorem)")))
        } else {
            (NonVacuity::Unknown, Some(Evidence::new(EvidenceKind::BoundedSearch, "no satisfying state found by bounded search; non-vacuity not established")))
        };
    };
    let cert = emit_certificate(
        &sat,
        &w,
        &[header.to_vec(), vec!["Non-vacuity witness: a concrete state satisfying every hypothesis.".into()]].concat(),
        &format!("{ns}.Witness"),
        "_witness",
    );
    let Ok((abs, rel)) = store.write_artifact(Artifact::Proofs, &format!("{base}.witness.lean"), &cert.source) else {
        return (NonVacuity::WitnessFound, None);
    };
    let c = check_file(&abs, &cert.theorems, opts.timeout);
    if c.accepted {
        (
            NonVacuity::KernelCheckedWitness,
            Some(
                Evidence::new(EvidenceKind::KernelChecked, "non-vacuity witness checked by the Lean kernel")
                    .with_artifact(rel)
                    .with_details(serde_json::to_value(&w).unwrap_or_default()),
            ),
        )
    } else {
        (
            NonVacuity::WitnessFound,
            Some(
                Evidence::new(EvidenceKind::BoundedSearch, format!("satisfying state found but Lean did not accept the witness: {}", c.reason))
                    .with_artifact(rel),
            ),
        )
    }
}

/// Re-check a saved counterexample: model re-evaluation (and Lean certificate if present).
pub fn recheck(file: &CounterexampleFile) -> Result<bool, String> {
    let ob = file.obligation.as_ref().ok_or("counterexample has no obligation")?;
    let asg: Assignment = file
        .counterexample
        .assignment
        .iter()
        .map(|(k, v)| serde_json::from_value(v.clone()).map(|x| (k.clone(), x)).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let ev = crate::eval::Evaluator::new(ob);
    Ok(crate::eval::violates(&ev, ob, &asg) && violation_is_robust(ob, &asg))
}
