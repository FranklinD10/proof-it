//! Proof-It testing itself.
//!
//! - Model self-check: two independent semantics of the model (Lean's and the
//!   evaluator's) must agree on every PROVEN obligation. Disagreement is a bug
//!   in Proof-It and turns the result into ERROR.
//! - Mutation testing: inject known bug classes into the code that formal
//!   targets depend on and measure whether the assurance result changes.

use proof_it_core::facts::ProgramFacts;
use proof_it_core::property::Property;
use proof_it_core::rng::Rng;
use proof_it_core::store::{ProofCache, RunStore};
use proof_it_core::types::*;
use proof_it_model::eval::search;
use proof_it_model::extract::{ExtractContext, Extraction};
use proof_it_model::formal::{FormalOptions, key, run as run_formal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

pub fn model_self_check(results: &mut [PropertyResult], extractions: &HashMap<String, Extraction>, seed: u64) -> (Vec<Finding>, StageRun) {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut checked = 0;
    for r in results.iter_mut().filter(|r| r.status() == ProofStatus::Proven) {
        let Some(ob) = extractions.get(&key(&r.property_id, &r.target)).and_then(|e| e.obligation.as_ref()) else {
            continue;
        };
        checked += 1;
        if let Some(cx) = search(ob, &mut Rng::new(seed), 100_000).counterexample {
            let msg = format!(
                "INTERNAL INCONSISTENCY: Lean accepted the theorem but the evaluator found a counterexample {}. Treat this result as untrusted and report a Proof-It bug.",
                serde_json::to_string(&cx).unwrap_or_default()
            );
            r.set_status(ProofStatus::Error, msg.clone());
            findings.push(Finding {
                id: format!("PROOFIT-SELFCHECK-{checked}"),
                rule_id: "PROOFIT-SELFCHECK".into(),
                property_id: Some(r.property_id.clone()),
                title: "Proof-It internal inconsistency".into(),
                source: FindingSource::Formal,
                severity: Severity::High,
                confidence: Confidence::High,
                location: r.location.clone(),
                description: msg,
                evidence: vec![Evidence::new(EvidenceKind::BoundedSearch, "evaluator disagrees with Lean")],
                recommendation: None,
                cwe: vec![],
                suppressed: None,
                baseline: None,
            });
        }
    }
    let n = findings.len();
    (
        findings,
        StageRun::new(
            "selfcheck",
            StageStatus::Ran,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
            format!("{checked} proven obligation(s) cross-checked against the evaluator; {n} inconsistency(ies)"),
        ),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutantResult {
    pub id: String,
    pub operator: String,
    pub location: SourceLocation,
    pub description: String,
    pub killed: bool,
    pub killed_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationReport {
    pub total: usize,
    pub killed: usize,
    pub survived: usize,
    pub score: Option<f64>,
    pub mutants: Vec<MutantResult>,
}

fn snapshot(
    props: &[&Property],
    facts: &ProgramFacts,
    ctx: &ExtractContext<'_>,
    store: &RunStore,
    cache: &ProofCache,
    opts: &FormalOptions,
) -> (HashMap<String, ProofStatus>, BTreeSet<String>) {
    let c2 = ExtractContext { facts, config: ctx.config, org: ctx.org };
    let out = run_formal(props, &c2, store, cache, opts);
    let formal = out.results.iter().map(|r| (r.key(), r.status())).collect();
    let security = facts.modules.iter().map(|m| m.file.clone()).collect::<BTreeSet<_>>();
    (formal, security)
}

/// Mutate the files formal targets depend on; a mutant is killed if a PROVEN
/// property stops being PROVEN, a new VIOLATED appears, or a new security
/// finding appears.
#[allow(clippy::too_many_arguments)]
pub fn mutation(
    props: &[&Property],
    facts: &ProgramFacts,
    files: &[proof_it_core::project::SourceFile],
    baseline: &[PropertyResult],
    extractions: &HashMap<String, Extraction>,
    ctx: &ExtractContext<'_>,
    cache: &ProofCache,
    opts: &FormalOptions,
    limit: usize,
) -> (MutationReport, StageRun) {
    let started = Instant::now();
    let formal_props: Vec<&Property> = props.iter().copied().filter(|p| p.spec.formal.is_some()).collect();
    let Ok(tmp) = tempfile::tempdir() else {
        return (
            MutationReport { total: 0, killed: 0, survived: 0, score: None, mutants: vec![] },
            StageRun::new("mutation", StageStatus::Failed, 0, "no temp dir"),
        );
    };
    let Ok(store) = RunStore::create(tmp.path()) else {
        return (
            MutationReport { total: 0, killed: 0, survived: 0, score: None, mutants: vec![] },
            StageRun::new("mutation", StageStatus::Failed, 0, "no scratch store"),
        );
    };
    let base: HashMap<String, ProofStatus> = baseline.iter().map(|r| (r.key(), r.status())).collect();
    let known: HashSet<String> = files.iter().map(|f| f.path.clone()).collect();
    // Lines of each file the formal targets depend on.
    let mut target_files: BTreeSet<String> = BTreeSet::new();
    for r in baseline.iter().filter(|r| matches!(r.status(), ProofStatus::Proven | ProofStatus::Violated | ProofStatus::Unproven)) {
        if let Some(e) = extractions.get(&r.key()) {
            target_files.extend(e.files.iter().cloned());
        }
    }
    let mut mutants = Vec::new();
    for f in files.iter().filter(|f| target_files.contains(&f.path)) {
        let Ok(text) = std::fs::read_to_string(&f.abs) else {
            continue;
        };
        mutants.extend(proof_it_lang_ts::mutants(&f.path, &text, &|_| true).into_iter().map(|m| (f, text.clone(), m)));
    }
    let total_generated = mutants.len();
    let mut results = Vec::new();
    for (f, text, m) in mutants.into_iter().take(limit) {
        let Some(mutated) = m.apply(&text) else {
            continue;
        };
        let Ok(a) = proof_it_lang_ts::analyze(&f.path, &mutated, &known) else {
            continue;
        };
        let before_findings: BTreeSet<String> =
            proof_it_lang_ts::analyze(&f.path, &text, &known).map(|x| x.findings.iter().map(|y| y.rule_id.clone()).collect()).unwrap_or_default();
        let after_findings: BTreeSet<String> = a.findings.iter().map(|y| y.rule_id.clone()).collect();
        let mut mfacts = facts.clone();
        if let Some(slot) = mfacts.modules.iter_mut().find(|x| x.file == f.path) {
            *slot = a.facts;
        }
        // Only properties whose model depends on the mutated file can change.
        let relevant: Vec<&Property> = formal_props
            .iter()
            .copied()
            .filter(|p| baseline.iter().any(|r| r.property_id == p.id() && extractions.get(&r.key()).is_some_and(|e| e.files.contains(&f.path))))
            .collect();
        let (snap, _) = snapshot(&relevant, &mfacts, ctx, &store, cache, opts);
        let mut killed_by = Vec::new();
        for (k, st) in base.iter().filter(|(k, _)| relevant.iter().any(|p| k.starts_with(&format!("{}::", p.id())))) {
            let now = snap.get(k);
            if *st == ProofStatus::Proven && now != Some(&ProofStatus::Proven) {
                killed_by.push(format!("{k}: PROVEN → {}", now.map_or("gone", |s| s.label())));
            }
        }
        for (k, st) in &snap {
            if *st == ProofStatus::Violated && base.get(k) != Some(&ProofStatus::Violated) {
                killed_by.push(format!("{k}: now VIOLATED"));
            }
        }
        for r in after_findings.difference(&before_findings) {
            killed_by.push(format!("new finding {r}"));
        }
        results.push(MutantResult {
            id: m.id,
            operator: m.operator,
            location: m.location,
            description: m.description,
            killed: !killed_by.is_empty(),
            killed_by,
        });
    }
    let killed = results.iter().filter(|r| r.killed).count();
    let total = results.len();
    #[allow(clippy::cast_precision_loss)]
    let score = (total > 0).then(|| killed as f64 / total as f64);
    let detail = format!(
        "{killed}/{total} mutant(s) detected{}",
        if total_generated > total { format!(" (limited to {limit} of {total_generated})") } else { String::new() }
    );
    (
        MutationReport { total, killed, survived: total - killed, score, mutants: results },
        StageRun::new("mutation", StageStatus::Ran, u64::try_from(started.elapsed().as_millis()).unwrap_or(0), detail),
    )
}
