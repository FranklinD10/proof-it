//! Change assurance: the layer between autonomous coding agents and production.
//!
//! A change is judged by evidence, not by the claims of whoever wrote it:
//!  - which modules it affects (changed files + everything that imports them),
//!  - which properties those modules carry (Proof-It decides, not the agent),
//!  - which previously PROVEN properties regressed (or silently vanished),
//!  - whether it weakens the verification policy itself (config, suppressions,
//!    properties) — reported separately from code changes and never auto-merged,
//!  - and the merge decision required by the (trusted) organisation policy.

use proof_it_core::config::{Config, MergePolicy, OrgPolicy, PolicyAction, Requirement, Suppression};
use proof_it_core::facts::ProgramFacts;
use proof_it_core::types::*;
use proof_it_model::extract::Extraction;
use proof_it_model::formal::key;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeDecision {
    #[serde(rename = "AUTO-MERGE ELIGIBLE")]
    AutoMergeEligible,
    #[serde(rename = "HUMAN REVIEW REQUIRED")]
    HumanReviewRequired,
    #[serde(rename = "BLOCKED")]
    Blocked,
}

impl MergeDecision {
    pub fn label(self) -> &'static str {
        match self {
            Self::AutoMergeEligible => "AUTO-MERGE ELIGIBLE",
            Self::HumanReviewRequired => "HUMAN REVIEW REQUIRED",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Merge {
    pub decision: MergeDecision,
    /// Why, most severe first.
    pub reasons: Vec<String>,
    /// Requirement checks per affected property.
    pub checks: Vec<RequirementCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementCheck {
    pub property_id: String,
    pub target: String,
    pub tier: String,
    pub requirement: Requirement,
    pub outcome: CheckOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckOutcome {
    Met,
    NeedsHuman,
    Blocks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    pub property_id: String,
    pub target: String,
    pub severity: Severity,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChange {
    pub what: String,
    /// Weakens a PROTECTED property (organisation policy) → blocks.
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeAssessment {
    pub range: String,
    pub agent: Option<String>,
    pub changed_files: Vec<String>,
    pub code_files: Vec<String>,
    pub policy_files: Vec<String>,
    pub affected_modules: Vec<String>,
    pub affected_properties: Vec<String>,
    pub baseline: Option<String>,
    pub regressions: Vec<Regression>,
    pub policy_changes: Vec<PolicyChange>,
    pub merge: Merge,
}

pub fn is_policy_file(path: &str) -> bool {
    path.starts_with(".proof-it/") && !path.starts_with(".proof-it/runs/") && !path.starts_with(".proof-it/cache/") && !path.starts_with(".proof-it/changes/")
}

/// Changed modules plus every module that (transitively) imports one of them.
pub fn affected_modules(facts: &ProgramFacts, changed: &[String]) -> Vec<String> {
    let mut importers: HashMap<&str, Vec<&str>> = HashMap::new();
    for m in &facts.modules {
        for i in &m.imports {
            importers.entry(i.as_str()).or_default().push(m.file.as_str());
        }
    }
    let mut out: BTreeSet<String> = changed.iter().filter(|c| facts.modules.iter().any(|m| &m.file == *c)).cloned().collect();
    let mut stack: Vec<String> = out.iter().cloned().collect();
    while let Some(f) = stack.pop() {
        for imp in importers.get(f.as_str()).into_iter().flatten() {
            if out.insert((*imp).to_owned()) {
                stack.push((*imp).to_owned());
            }
        }
    }
    out.into_iter().collect()
}

/// Properties affected by the change: Proof-It's own applicability analysis.
pub fn affected_properties(
    results: &[PropertyResult],
    findings: &[Finding],
    extractions: &HashMap<String, Extraction>,
    affected: &[String],
    facts: &ProgramFacts,
    props: &[&proof_it_core::property::Property],
) -> Vec<String> {
    let set: BTreeSet<&str> = affected.iter().map(String::as_str).collect();
    let mut out = BTreeSet::new();
    for r in results {
        let files: Vec<String> = extractions.get(&key(&r.property_id, &r.target)).map(|e| e.files.clone()).unwrap_or_default();
        let touched = files.iter().any(|f| set.contains(f.as_str())) || r.location.as_ref().is_some_and(|l| set.contains(l.file.as_str()));
        if touched {
            out.insert(r.property_id.clone());
        }
    }
    for f in findings {
        if let (Some(p), Some(l)) = (&f.property_id, &f.location)
            && set.contains(l.file.as_str())
        {
            out.insert(p.clone());
        }
    }
    // Non-formal properties whose applicability signals match the changed code.
    for p in props.iter().filter(|p| p.spec.formal.is_none() && !p.signals.is_empty()) {
        if facts.texts.iter().any(|(file, text)| set.contains(file.as_str()) && p.signal_matches(text)) {
            out.insert(p.id().to_owned());
        }
    }
    out.into_iter().collect()
}

/// PROVEN before, not PROVEN now (or the target vanished); and new violations.
pub fn regressions(before: &[PropertyResult], after: &[PropertyResult]) -> Vec<Regression> {
    let now: HashMap<String, &PropertyResult> = after.iter().map(|r| (r.key(), r)).collect();
    let then: HashMap<String, &PropertyResult> = before.iter().map(|r| (r.key(), r)).collect();
    let mut out = Vec::new();
    for b in before.iter().filter(|b| b.status() == ProofStatus::Proven) {
        match now.get(&b.key()) {
            Some(a) if a.status() == ProofStatus::Proven => {}
            Some(a) => out.push(Regression {
                property_id: b.property_id.clone(),
                target: b.target.clone(),
                severity: b.severity,
                before: "PROVEN".into(),
                after: a.status().label().into(),
            }),
            None => {
                // The target disappeared. If the property still has proven targets elsewhere this may be a
                // rename; it is still reported: an invariant that was proven is no longer being verified.
                out.push(Regression {
                    property_id: b.property_id.clone(),
                    target: b.target.clone(),
                    severity: b.severity,
                    before: "PROVEN".into(),
                    after: "NO LONGER VERIFIED (target not found)".into(),
                });
            }
        }
    }
    for a in after.iter().filter(|a| a.status() == ProofStatus::Violated && a.spec_source.is_authoritative()) {
        if then.get(&a.key()).is_none_or(|b| b.status() != ProofStatus::Violated && b.status() != ProofStatus::Proven) {
            out.push(Regression {
                property_id: a.property_id.clone(),
                target: a.target.clone(),
                severity: a.severity,
                before: then.get(&a.key()).map_or_else(|| "absent".into(), |b| b.status().label().into()),
                after: "VIOLATED".into(),
            });
        }
    }
    out
}

fn weaker(a: PolicyAction, b: PolicyAction) -> bool {
    let rank = |x: PolicyAction| match x {
        PolicyAction::Fail => 2,
        PolicyAction::Warn => 1,
        PolicyAction::Ignore => 0,
    };
    rank(b) < rank(a)
}

/// Semantic comparison of verification policy before → after the change.
pub fn policy_changes(before: &Config, after: &Config, sup_before: &[Suppression], sup_after: &[Suppression], org: &OrgPolicy) -> Vec<PolicyChange> {
    let protected = |id: &str| org.protected_properties.iter().any(|p| p.eq_ignore_ascii_case(id));
    let mut out = Vec::new();
    let mut push = |what: String, prot: bool| out.push(PolicyChange { what, protected: prot });
    for x in after.properties.exclude.iter().filter(|x| !before.properties.exclude.contains(x)) {
        push(format!("property selector `{x}` newly EXCLUDED from verification"), protected(x));
    }
    if !after.properties.include.is_empty() && after.properties.include != before.properties.include {
        push(
            format!("property include-list narrowed to [{}]", after.properties.include.join(", ")),
            org.protected_properties.iter().any(|p| !after.properties.include.iter().any(|i| i.eq_ignore_ascii_case(p))),
        );
    }
    for g in after.exclude.iter().filter(|x| !before.exclude.contains(x)) {
        push(format!("path `{g}` newly excluded from analysis (code hidden from the analyzer)"), false);
    }
    for (name, b, a) in [
        ("violated", before.policy.violated, after.policy.violated),
        ("critical_security", before.policy.critical_security, after.policy.critical_security),
        ("high_security", before.policy.high_security, after.policy.high_security),
        ("unproven", before.policy.unproven, after.policy.unproven),
        ("error", before.policy.error, after.policy.error),
    ] {
        if weaker(b, a) {
            push(format!("policy.{name} weakened from {b:?} to {a:?}"), name == "violated" && !org.protected_properties.is_empty());
        }
    }
    for (name, b, a) in [
        ("static", before.analysis.r#static, after.analysis.r#static),
        ("security", before.analysis.security, after.analysis.security),
        ("secrets", before.analysis.secrets, after.analysis.secrets),
        ("dependencies", before.analysis.dependencies, after.analysis.dependencies),
        ("formal", before.analysis.formal, after.analysis.formal),
        ("fuzzing", before.analysis.fuzzing, after.analysis.fuzzing),
    ] {
        if b && !a {
            push(format!("analysis.{name} disabled"), name == "formal" && !org.protected_properties.is_empty());
        }
    }
    for g in after.authorization.guard_functions.iter().filter(|x| !before.authorization.guard_functions.contains(x)) {
        push(format!("`{g}` newly TRUSTED as an ownership guard (proofs now assume it enforces ownership)"), protected("AUTHZ-001"));
    }
    for sm in &before.state_machines {
        let now = after.state_machines.iter().find(|x| x.r#type == sm.r#type);
        for t in &sm.terminal {
            if now.is_none_or(|n| !n.terminal.contains(t)) {
                push(format!("terminal state {t} of {} removed from the specification", sm.r#type), protected("STATE-001"));
            }
        }
        for f in &sm.forbidden {
            if now.is_none_or(|n| !n.forbidden.contains(f)) {
                push(format!("forbidden transition {} → {} of {} removed from the specification", f.0, f.1, sm.r#type), protected("STATE-002"));
            }
        }
    }
    for s in sup_after.iter().filter(|s| !sup_before.contains(s)) {
        push(
            format!("new suppression of `{}`{}: \"{}\"", s.finding, s.file.as_ref().map(|f| format!(" in {f}")).unwrap_or_default(), s.reason),
            protected(&s.finding),
        );
    }
    out
}

fn tier(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        _ => "normal",
    }
}

#[allow(clippy::too_many_arguments)]
pub fn decide(
    policy: &MergePolicy,
    affected_props: &[String],
    results: &[PropertyResult],
    findings: &[Finding],
    affected_files: &[String],
    regressions: &[Regression],
    policy_changes: &[PolicyChange],
    attack_ran: bool,
    baseline_present: bool,
) -> Merge {
    let files: BTreeSet<&str> = affected_files.iter().map(String::as_str).collect();
    let mut checks = Vec::new();
    let mut reasons_block = Vec::new();
    let mut reasons_human = Vec::new();
    let by_prop: BTreeMap<&str, Vec<&PropertyResult>> = results.iter().fold(BTreeMap::new(), |mut m, r| {
        m.entry(r.property_id.as_str()).or_insert_with(Vec::new).push(r);
        m
    });
    let security_blockers: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.suppressed.is_none() && f.severity >= Severity::High && f.location.as_ref().is_some_and(|l| files.contains(l.file.as_str())))
        .collect();
    for pid in affected_props {
        for r in by_prop.get(pid.as_str()).into_iter().flatten() {
            if r.suppressed.is_some() || r.status() == ProofStatus::NotApplicable {
                continue;
            }
            let in_change = r.in_change.unwrap_or(true);
            let t = tier(r.severity);
            let reqs = match t {
                "critical" => &policy.critical,
                "high" => &policy.high,
                _ => &policy.normal,
            };
            for req in reqs {
                let (outcome, detail) = match req {
                    Requirement::FormalProof => match r.status() {
                        ProofStatus::Proven if r.spec_source.is_authoritative() => (CheckOutcome::Met, "kernel-checked, non-vacuous".to_owned()),
                        ProofStatus::Proven => (CheckOutcome::NeedsHuman, format!("proven against a {} specification", r.spec_source.label())),
                        ProofStatus::Violated => (CheckOutcome::Blocks, "VIOLATED".into()),
                        s => (CheckOutcome::NeedsHuman, format!("{} — no formal proof", s.label())),
                    },
                    Requirement::NoViolation => match (r.status(), r.spec_source.is_authoritative(), in_change) {
                        (ProofStatus::Violated, true, true) => (CheckOutcome::Blocks, "counterexample exists".into()),
                        (ProofStatus::Violated, false, _) => (CheckOutcome::NeedsHuman, format!("violates an {} specification", r.spec_source.label())),
                        _ => (CheckOutcome::Met, "no counterexample".into()),
                    },
                    Requirement::SecurityPass => {
                        let mine: Vec<&&Finding> = security_blockers
                            .iter()
                            .filter(|f| {
                                f.property_id.as_deref() == Some(pid.as_str())
                                    || r.location.as_ref().zip(f.location.as_ref()).is_some_and(|(a, b)| a.file == b.file)
                            })
                            .collect();
                        if mine.is_empty() {
                            (CheckOutcome::Met, "no high/critical findings".into())
                        } else {
                            (CheckOutcome::Blocks, format!("{} high/critical finding(s)", mine.len()))
                        }
                    }
                    Requirement::AdversarialTest => {
                        if !attack_ran {
                            (CheckOutcome::NeedsHuman, "adversarial testing did not run (pass --allow-exec)".into())
                        } else if r.evidence.iter().any(|e| e.kind == EvidenceKind::ReplayedAgainstCode && e.summary.contains("violate")) {
                            (CheckOutcome::Blocks, "executed input violates the property".into())
                        } else {
                            (CheckOutcome::Met, "no executed counterexample".into())
                        }
                    }
                    Requirement::RegressionPass => {
                        if !baseline_present {
                            (CheckOutcome::NeedsHuman, "no baseline: regressions cannot be established".into())
                        } else if regressions.iter().any(|g| g.property_id == r.property_id && g.target == r.target) {
                            (CheckOutcome::Blocks, "regressed".into())
                        } else {
                            (CheckOutcome::Met, "no regression".into())
                        }
                    }
                };
                let msg = format!("{pid} [{t}] {req:?} at {}: {detail}", r.target);
                match outcome {
                    CheckOutcome::Blocks => reasons_block.push(msg),
                    CheckOutcome::NeedsHuman => reasons_human.push(msg),
                    CheckOutcome::Met => {}
                }
                checks.push(RequirementCheck { property_id: pid.clone(), target: r.target.clone(), tier: t.into(), requirement: *req, outcome, detail });
            }
        }
    }
    for f in &security_blockers {
        if f.property_id.as_ref().is_none_or(|p| !affected_props.contains(p)) {
            reasons_block.push(format!(
                "{} {} in changed code ({})",
                f.severity.label(),
                f.rule_id,
                f.location.as_ref().map(|l| l.to_string()).unwrap_or_default()
            ));
        }
    }
    for g in regressions {
        reasons_block.push(format!("REGRESSION {} {}: {} → {}", g.property_id, g.target, g.before, g.after));
    }
    for p in policy_changes {
        if p.protected {
            reasons_block.push(format!("weakens a PROTECTED property: {}", p.what));
        } else if policy.policy_changes_require_human {
            reasons_human.push(format!("verification-policy change: {}", p.what));
        }
    }
    reasons_block.sort();
    reasons_block.dedup();
    reasons_human.sort();
    reasons_human.dedup();
    // The decision itself is the Lean-specified `decide` (proof_it_core::decision).
    use proof_it_core::decision::{Decision, Outcome, decide as decide_model};
    let outcomes: Vec<Outcome> = checks
        .iter()
        .map(|c| match c.outcome {
            CheckOutcome::Met => Outcome::Met,
            CheckOutcome::NeedsHuman => Outcome::NeedsHuman,
            CheckOutcome::Blocks => Outcome::Blocks,
        })
        .collect();
    let block_flag = reasons_block.len() > checks.iter().filter(|c| c.outcome == CheckOutcome::Blocks).count();
    let human_flag = reasons_human.len() > checks.iter().filter(|c| c.outcome == CheckOutcome::NeedsHuman).count();
    let decision = match decide_model(&outcomes, block_flag, human_flag) {
        Decision::Blocked => MergeDecision::Blocked,
        Decision::HumanReview => MergeDecision::HumanReviewRequired,
        Decision::AutoMerge => MergeDecision::AutoMergeEligible,
    };
    Merge { decision, reasons: [reasons_block, reasons_human].concat(), checks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_it_core::config::Config;

    #[test]
    fn detects_policy_weakening() {
        let before = Config::default();
        let mut after = Config::default();
        after.properties.exclude.push("AUTHZ-001".into());
        after.policy.violated = PolicyAction::Warn;
        after.authorization.guard_functions.push("trustMe".into());
        let org = OrgPolicy { protected_properties: vec!["AUTHZ-001".into()], ..OrgPolicy::default() };
        let ch = policy_changes(&before, &after, &[], &[Suppression { finding: "SEC-SQLI".into(), file: None, reason: "it is fine trust me".into() }], &org);
        assert!(ch.iter().any(|c| c.protected && c.what.contains("EXCLUDED")));
        assert!(ch.iter().any(|c| c.what.contains("weakened")));
        assert!(ch.iter().any(|c| c.protected && c.what.contains("trustMe")));
        assert!(ch.iter().any(|c| !c.protected && c.what.contains("suppression")));
    }

    #[test]
    fn regressions_include_vanished_targets() {
        let mut a = PropertyResult::new("P-001", "p", "t1", ProofStatus::Unproven, Severity::High, SpecSource::Library, "");
        let acc = KernelAcceptance::from_lean_check(vec![], vec![], String::new(), String::new());
        assert!(a.prove(&acc, NonVacuity::KernelCheckedWitness).is_ok());
        let before = vec![a.clone()];
        let after: Vec<PropertyResult> = vec![];
        let g = regressions(&before, &after);
        assert_eq!(g.len(), 1);
        assert!(g[0].after.contains("NO LONGER VERIFIED"));
        let mut b = a.clone();
        b.set_status(ProofStatus::Violated, "x");
        assert_eq!(regressions(&before, &[b])[0].after, "VIOLATED");
    }

    #[test]
    fn merge_decisions() {
        let pol = MergePolicy::default();
        let mut v = PropertyResult::new("AUTHZ-001", "iso", "GET /x", ProofStatus::Violated, Severity::Critical, SpecSource::Library, "");
        v.in_change = Some(true);
        let m = decide(&pol, &["AUTHZ-001".into()], &[v], &[], &[], &[], &[], true, true);
        assert_eq!(m.decision, MergeDecision::Blocked);
        let u = PropertyResult::new("AUTHZ-001", "iso", "GET /x", ProofStatus::Unproven, Severity::Critical, SpecSource::Library, "");
        let m = decide(&pol, &["AUTHZ-001".into()], &[u], &[], &[], &[], &[], true, true);
        assert_eq!(m.decision, MergeDecision::HumanReviewRequired);
        let mut p = PropertyResult::new("AUTHZ-001", "iso", "GET /x", ProofStatus::Unproven, Severity::Critical, SpecSource::Library, "");
        let acc = KernelAcceptance::from_lean_check(vec![], vec![], String::new(), String::new());
        assert!(p.prove(&acc, NonVacuity::KernelCheckedWitness).is_ok());
        let m = decide(&pol, &["AUTHZ-001".into()], &[p.clone()], &[], &[], &[], &[], true, true);
        assert_eq!(m.decision, MergeDecision::AutoMergeEligible, "{:?}", m.reasons);
        // Same proof but no baseline: regression cannot be established → human.
        let m = decide(&pol, &["AUTHZ-001".into()], &[p], &[], &[], &[], &[], true, false);
        assert_eq!(m.decision, MergeDecision::HumanReviewRequired);
    }
}
