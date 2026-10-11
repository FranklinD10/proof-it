//! Verdict policy, assurance levels and proof debt.
//!
//! Everything that can fail a run is listed in `reasons` so every output can
//! say exactly why. The assurance level answers "how much evidence does this
//! code have?" — each level states what is missing for the next.

use proof_it_core::config::{Config, PolicyAction};
use proof_it_core::error::ExitCode;
use proof_it_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict: AssuranceVerdict,
    pub exit_code: u8,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub counts: BTreeMap<String, usize>,
    pub severities: BTreeMap<String, usize>,
    /// Source code that was not analysed (unparseable or skipped files).
    #[serde(default)]
    pub gaps: Vec<String>,
}

pub fn compute(results: &[PropertyResult], findings: &[Finding], stages: &[StageRun], cfg: &Config, scoped: bool, gaps: &[String]) -> Verdict {
    let mut counts: BTreeMap<String, usize> = ProofStatus::ALL.iter().map(|s| (s.label().to_owned(), 0)).collect();
    for r in results {
        *counts.entry(r.status().label().to_owned()).or_default() += 1;
    }
    let active: Vec<&Finding> = findings.iter().filter(|f| f.suppressed.is_none()).collect();
    let mut severities: BTreeMap<String, usize> = Severity::ALL.iter().map(|s| (s.label().to_owned(), 0)).collect();
    for f in &active {
        *severities.entry(f.severity.label().to_owned()).or_default() += 1;
    }
    let (mut reasons, mut warnings) = (Vec::new(), Vec::new());
    let counted = |in_change: Option<bool>| !scoped || in_change != Some(false);
    for r in results.iter().filter(|r| r.suppressed.is_none()) {
        let msg = format!("{} {} at {}", r.property_id, r.status().label(), r.target);
        match r.status() {
            ProofStatus::Violated => {
                // A violation of an INFERRED or AI-generated specification warns: the requirement itself is a guess.
                let action = if r.spec_source.is_authoritative() { cfg.policy.violated } else { PolicyAction::Warn };
                if action == PolicyAction::Fail && counted(r.in_change) {
                    reasons.push(msg);
                } else if action != PolicyAction::Ignore {
                    warnings.push(format!(
                        "{msg}{}",
                        if r.spec_source.is_authoritative() {
                            if counted(r.in_change) { "" } else { " (outside the change)" }
                        } else {
                            " (non-authoritative specification)"
                        }
                    ));
                }
            }
            ProofStatus::Unproven => match cfg.policy.unproven {
                PolicyAction::Fail if counted(r.in_change) => reasons.push(msg),
                PolicyAction::Ignore => {}
                _ => warnings.push(msg),
            },
            ProofStatus::Error => match cfg.policy.error {
                PolicyAction::Fail => reasons.push(msg),
                _ => warnings.push(format!("{msg}: {}", r.reason)),
            },
            _ => {}
        }
    }
    for f in &active {
        let in_scope = !scoped || f.baseline != Some(BaselineState::Existing);
        let at = f.location.as_ref().map(|l| format!(" ({l})")).unwrap_or_default();
        let action = match f.severity {
            Severity::Critical => cfg.policy.critical_security,
            Severity::High => cfg.policy.high_security,
            _ => continue,
        };
        let msg = format!("{} {}{at}", f.severity.label(), f.rule_id);
        match action {
            PolicyAction::Fail if in_scope => reasons.push(msg),
            PolicyAction::Ignore => {}
            _ => warnings.push(format!("{msg}{}", if in_scope { "" } else { " (inherited)" })),
        }
    }
    for s in stages.iter().filter(|s| matches!(s.status, StageStatus::Failed | StageStatus::TimedOut)) {
        warnings.push(format!("stage {} {:?}: {}", s.name, s.status, s.detail.clone().unwrap_or_default()));
    }
    // Unanalysed code can hide anything: such a run is never PASSED. A violation
    // found in the analysed part still fails it.
    let verdict = if !reasons.is_empty() {
        AssuranceVerdict::Failed
    } else if !gaps.is_empty() {
        AssuranceVerdict::Incomplete
    } else if !warnings.is_empty() {
        AssuranceVerdict::PassedWithWarnings
    } else {
        AssuranceVerdict::Passed
    };
    let exit_code = match verdict {
        AssuranceVerdict::Failed => ExitCode::AssuranceFailed,
        AssuranceVerdict::Incomplete => ExitCode::AnalysisError,
        _ => ExitCode::Passed,
    } as u8;
    Verdict { verdict, exit_code, reasons, warnings, counts, severities, gaps: gaps.to_vec() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssuranceLevel {
    pub level: u8,
    pub label: String,
    /// What is missing to reach the next level.
    pub next: Option<String>,
}

/// Evidence-based assurance level (docs/evidence-model.md):
///  0 nothing meaningful established;
///  1 static + security analysis ran (no analyzer silently skipped);
///  2 … and no unsuppressed HIGH/CRITICAL findings;
///  3 … and every applicable CRITICAL/HIGH property is formally modeled;
///  4 … and every such property is PROVEN (authoritative, non-vacuous spec);
///  5 … and adversarial testing ran against the code with no violation.
///  6 (system-level invariants) is not attainable by Proof-It today.
pub fn assurance_level(results: &[PropertyResult], findings: &[Finding], stages: &[StageRun], gaps: &[String]) -> AssuranceLevel {
    let ran = |n: &str| stages.iter().any(|s| s.name == n && s.status == StageStatus::Ran);
    let mk = |level: u8, label: &str, next: Option<String>| AssuranceLevel { level, label: label.to_owned(), next };
    if !gaps.is_empty() {
        return mk(0, "analysis incomplete", Some(format!("{} source file(s) were not analysed; fix them or exclude them explicitly", gaps.len())));
    }
    if !(ran("static") && ran("security")) {
        return mk(0, "no meaningful assurance", Some("run static and security analysis".into()));
    }
    let important: Vec<&PropertyResult> =
        results.iter().filter(|r| r.severity >= Severity::High && r.status() != ProofStatus::NotApplicable && r.suppressed.is_none()).collect();
    let blocking = findings.iter().filter(|f| f.suppressed.is_none() && f.severity >= Severity::High).count();
    if blocking > 0 {
        return mk(1, "static and security analysis ran", Some(format!("resolve {blocking} HIGH/CRITICAL finding(s)")));
    }
    let unmodeled = important.iter().filter(|r| r.status() == ProofStatus::NotModeled).count();
    if unmodeled > 0 || !ran("formal") {
        return mk(2, "static and security analysis passed", Some(format!("{unmodeled} important property(ies) have no formal model")));
    }
    let unproven: Vec<&&PropertyResult> = important.iter().filter(|r| r.status() != ProofStatus::Proven || !r.spec_source.is_authoritative()).collect();
    if !unproven.is_empty() {
        return mk(
            3,
            "important properties modeled",
            Some(format!("{} important property target(s) are not PROVEN against an authoritative specification", unproven.len())),
        );
    }
    if !ran("attack") || findings.iter().any(|f| f.source == FindingSource::Attack && f.suppressed.is_none()) {
        return mk(
            4,
            "important properties formally proven",
            Some("run adversarial testing against the implementation (--allow-exec) without violations".into()),
        );
    }
    mk(5, "formal proof + security analysis + adversarial testing", Some("level 6 (system-level invariants) is not attainable by Proof-It today".into()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofDebt {
    pub critical_unproven: usize,
    pub high_unproven: usize,
    pub not_modeled: usize,
    pub proven: usize,
    pub total_applicable: usize,
}

pub fn proof_debt(results: &[PropertyResult]) -> ProofDebt {
    let mut d = ProofDebt::default();
    for r in results.iter().filter(|r| r.status() != ProofStatus::NotApplicable) {
        d.total_applicable += 1;
        match r.status() {
            ProofStatus::Proven => d.proven += 1,
            ProofStatus::NotModeled => d.not_modeled += 1,
            ProofStatus::Unproven | ProofStatus::Error | ProofStatus::Violated if r.severity == Severity::Critical => d.critical_unproven += 1,
            ProofStatus::Unproven | ProofStatus::Error | ProofStatus::Violated if r.severity == Severity::High => d.high_unproven += 1,
            _ => {}
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanalysed_code_never_passes() {
        let cfg = Config::default();
        let gaps = vec!["src/a.ts: could not be parsed (Unexpected token)".to_owned()];
        let v = compute(&[], &[], &[], &cfg, false, &gaps);
        assert_eq!(v.verdict, AssuranceVerdict::Incomplete);
        assert_eq!(v.exit_code, ExitCode::AnalysisError as u8);
        assert_eq!(compute(&[], &[], &[], &cfg, false, &[]).verdict, AssuranceVerdict::Passed);
        assert_eq!(assurance_level(&[], &[], &[], &gaps).level, 0);
    }

    #[test]
    fn coverage_gaps_are_source_files_only() {
        let parse = vec![("src/a.ts".to_owned(), "Unexpected token".to_owned())];
        let skipped = vec![
            ("data/export.csv".to_owned(), "larger than 2097152 bytes".to_owned()),
            ("src/huge.js".to_owned(), "larger than 2097152 bytes".to_owned()),
            ("public/app.min.js".to_owned(), "larger than 2097152 bytes".to_owned()),
        ];
        let g = crate::pipeline::coverage_gaps(&parse, &skipped, &[]);
        assert_eq!(g.len(), 2, "{g:?}");
        assert!(g[0].starts_with("src/a.ts") && g[1].starts_with("src/huge.js"));
    }
}
