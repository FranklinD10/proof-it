//! Result vocabulary shared by every engine.
//!
//! The meaning of each status is part of Proof-It's public contract
//! (docs/evidence-model.md). The type system enforces the most important rule:
//! a [`PropertyResult`] can only be PROVEN through [`PropertyResult::prove`],
//! which requires a [`KernelAcceptance`] — a value only the Lean runner can
//! construct.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Outcome of evaluating one property against one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatus {
    /// The Lean kernel accepted a non-vacuous proof for the extracted model.
    Proven,
    /// A concrete counterexample exists (model-level and/or executed against the code).
    Violated,
    /// Neither proof nor robust counterexample. Not evidence of a bug.
    Unproven,
    /// The property applies but no model/extractor exists for this target.
    NotModeled,
    /// No code matched the property's applicability conditions.
    NotApplicable,
    /// The engine itself failed.
    Error,
}

impl ProofStatus {
    pub const ALL: [ProofStatus; 6] = [Self::Proven, Self::Violated, Self::Unproven, Self::NotModeled, Self::NotApplicable, Self::Error];
    pub fn label(self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::Violated => "VIOLATED",
            Self::Unproven => "UNPROVEN",
            Self::NotModeled => "NOT MODELED",
            Self::NotApplicable => "NOT APPLICABLE",
            Self::Error => "ERROR",
        }
    }
}

impl fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [Self::Info, Self::Low, Self::Medium, Self::High, Self::Critical];
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "INFO" => Some(Self::Info),
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSource {
    Static,
    Security,
    Secrets,
    Dependencies,
    Formal,
    Attack,
    External,
    Policy,
}

/// Where a specification came from. Never hidden: a proof of an AI-generated or
/// inferred specification is a weaker claim than a proof of a human-owned one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecSource {
    /// Shipped with Proof-It.
    Library,
    /// Organisation policy file outside the repository (trusted).
    Organization,
    /// Repository-defined by a human.
    Project,
    /// Proposed by an AI agent; a candidate until accepted.
    AiGenerated,
    /// Inferred by a Proof-It heuristic.
    Inferred,
}

impl SpecSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Organization => "organization",
            Self::Project => "project",
            Self::AiGenerated => "ai-generated",
            Self::Inferred => "inferred",
        }
    }
    /// Whether a violation of this specification is authoritative enough to fail a run.
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Library | Self::Organization | Self::Project)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Repository-relative path with forward slashes.
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// Short excerpt; secrets are redacted before this is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self { file: file.into(), line, column: None, end_line: None, snippet: None }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// The kind of evidence behind a result, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    KernelChecked,
    KernelCheckedCounterexample,
    ReplayedAgainstCode,
    BoundedSearch,
    StaticPattern,
    ExternalTool,
    Assumption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub summary: String,
    /// Path inside the run directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Evidence {
    pub fn new(kind: EvidenceKind, summary: impl Into<String>) -> Self {
        Self { kind, summary: summary.into(), artifact: None, details: None }
    }
    pub fn with_artifact(mut self, a: impl Into<String>) -> Self {
        self.artifact = Some(a.into());
        self
    }
    pub fn with_details(mut self, d: serde_json::Value) -> Self {
        self.details = Some(d);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonVacuity {
    /// Lean checked a concrete state satisfying every hypothesis.
    KernelCheckedWitness,
    /// A satisfying state exists but its certificate was not checked.
    WitnessFound,
    /// Not established either way.
    Unknown,
    /// Exhaustive search shows the hypotheses are unsatisfiable.
    Vacuous,
}

/// Proof of Lean kernel acceptance. Only `proof_it_model::lean` constructs it
/// (via [`KernelAcceptance::from_lean_check`]) after the full acceptance check.
/// `#[non_exhaustive]` forbids struct-literal construction outside this crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KernelAcceptance {
    pub theorems: Vec<String>,
    pub axioms: Vec<String>,
    pub toolchain: String,
    pub proof_file: String,
}

impl KernelAcceptance {
    /// Called by the Lean runner only after: no forbidden constructs, exit 0,
    /// no error diagnostics, axiom report present for every theorem, and every
    /// axiom within the foundation set. Keep that list in sync with
    /// `proof_it_model::lean::runner::check`.
    #[doc(hidden)]
    pub fn from_lean_check(theorems: Vec<String>, axioms: Vec<String>, toolchain: String, proof_file: String) -> Self {
        Self { theorems, axioms, toolchain, proof_file }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofQuality {
    pub kernel_checked: bool,
    pub axioms: Vec<String>,
    pub extra_axioms: Vec<String>,
    /// The code→model translation is not itself verified. Always true today.
    pub unverified_translation: bool,
    pub opaque_predicates: Vec<String>,
    pub non_vacuity: NonVacuity,
    /// Whether the proof script came from an (untrusted) agent-provided hint.
    pub proof_from_hint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterexampleStep {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<serde_json::Value>,
}

impl CounterexampleStep {
    pub fn new(action: impl Into<String>) -> Self {
        Self { action: action.into(), location: None, values: None }
    }
    pub fn at(mut self, loc: Option<SourceLocation>) -> Self {
        self.location = loc;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub attempted: bool,
    pub reproduced: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterexample {
    pub property_id: String,
    pub target: String,
    pub assignment: BTreeMap<String, serde_json::Value>,
    pub steps: Vec<CounterexampleStep>,
    pub violated_invariant: String,
    pub seed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lean_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayResult>,
}

/// Formalization level reached (docs/formal-verification.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FormalizationLevel(pub u8);

impl FormalizationLevel {
    pub const STATIC: Self = Self(0);
    pub const MATCHED: Self = Self(1);
    pub const MODELED: Self = Self(2);
    pub const LEAN: Self = Self(3);
}

/// One property evaluated against one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyResult {
    pub property_id: String,
    pub property_name: String,
    pub target: String,
    status: ProofStatus,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    pub reason: String,
    pub evidence: Vec<Evidence>,
    pub assumptions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<ProofQuality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterexample: Option<Counterexample>,
    pub level: FormalizationLevel,
    pub spec_source: SpecSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theorem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<String>,
    /// Diff mode: whether the target lies in the changed/affected code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_change: Option<bool>,
}

impl PropertyResult {
    /// A result in any status except PROVEN.
    ///
    /// # Panics
    /// If called with [`ProofStatus::Proven`]; use [`PropertyResult::prove`].
    pub fn new(
        property_id: &str,
        property_name: &str,
        target: &str,
        status: ProofStatus,
        severity: Severity,
        spec_source: SpecSource,
        reason: impl Into<String>,
    ) -> Self {
        assert!(status != ProofStatus::Proven, "PROVEN requires KernelAcceptance; use PropertyResult::prove");
        Self {
            property_id: property_id.to_owned(),
            property_name: property_name.to_owned(),
            target: target.to_owned(),
            status,
            severity,
            location: None,
            reason: reason.into(),
            evidence: Vec::new(),
            assumptions: Vec::new(),
            quality: None,
            counterexample: None,
            level: FormalizationLevel::MATCHED,
            spec_source,
            theorem: None,
            recommendation: None,
            suppressed: None,
            in_change: None,
        }
    }

    pub fn status(&self) -> ProofStatus {
        self.status
    }

    /// The only way to reach PROVEN: requires a kernel acceptance and a
    /// non-vacuity status other than `Vacuous`.
    pub fn prove(&mut self, acceptance: &KernelAcceptance, non_vacuity: NonVacuity) -> Result<(), &'static str> {
        if non_vacuity == NonVacuity::Vacuous {
            return Err("a vacuous theorem cannot establish a property");
        }
        let q = self.quality.get_or_insert(ProofQuality {
            kernel_checked: false,
            axioms: vec![],
            extra_axioms: vec![],
            unverified_translation: true,
            opaque_predicates: vec![],
            non_vacuity,
            proof_from_hint: false,
        });
        q.kernel_checked = true;
        q.axioms.clone_from(&acceptance.axioms);
        q.non_vacuity = non_vacuity;
        self.status = ProofStatus::Proven;
        self.level = FormalizationLevel::LEAN;
        Ok(())
    }

    /// Downgrade or change to any non-PROVEN status (e.g. an executed
    /// counterexample overrides a model-level proof).
    pub fn set_status(&mut self, status: ProofStatus, reason: impl Into<String>) {
        assert!(status != ProofStatus::Proven, "PROVEN requires KernelAcceptance; use PropertyResult::prove");
        self.status = status;
        self.reason = reason.into();
    }

    pub fn key(&self) -> String {
        format!("{}::{}", self.property_id, self.target)
    }
}

/// A non-formal finding (static, security, secrets, dependency, external, attack).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable fingerprint for suppression and baseline comparison.
    pub id: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_id: Option<String>,
    pub title: String,
    pub source: FindingSource,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    pub description: String,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineState {
    New,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StageStatus {
    Ran,
    Skipped,
    NotInstalled,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageRun {
    pub name: String,
    pub status: StageStatus,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl StageRun {
    pub fn new(name: &str, status: StageStatus, duration_ms: u64, detail: impl Into<String>) -> Self {
        Self { name: name.to_owned(), status, duration_ms, detail: Some(detail.into()), version: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceVerdict {
    Passed,
    PassedWithWarnings,
    Failed,
    /// Part of the code could not be analysed (parse errors, skipped source files):
    /// the run cannot pass, whatever the analysed part shows.
    Incomplete,
}

impl AssuranceVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::PassedWithWarnings => "PASSED WITH WARNINGS",
            Self::Failed => "FAILED",
            Self::Incomplete => "INCOMPLETE",
        }
    }
}

/// Stable finding fingerprint: rule + file + whitespace-normalised snippet (+ extra).
/// Line numbers are deliberately excluded so unrelated edits do not change ids.
pub fn fingerprint(rule_id: &str, loc: Option<&SourceLocation>, extra: &str) -> String {
    let snippet: String = loc.and_then(|l| l.snippet.as_deref()).unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
    let file = loc.map_or("", |l| l.file.as_str());
    let h = crate::store::sha256_hex(format!("{rule_id}|{file}|{snippet}|{extra}").as_bytes());
    format!("{rule_id}-{}", &h[..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "PROVEN requires KernelAcceptance")]
    fn proven_cannot_be_constructed_directly() {
        let _ = PropertyResult::new("X-001", "x", "t", ProofStatus::Proven, Severity::High, SpecSource::Library, "");
    }

    #[test]
    fn vacuous_proof_is_refused() {
        let mut r = PropertyResult::new("X-001", "x", "t", ProofStatus::Unproven, Severity::High, SpecSource::Library, "");
        let acc = KernelAcceptance::from_lean_check(vec!["t".into()], vec![], "lean".into(), "f".into());
        assert!(r.prove(&acc, NonVacuity::Vacuous).is_err());
        assert_eq!(r.status(), ProofStatus::Unproven);
        assert!(r.prove(&acc, NonVacuity::KernelCheckedWitness).is_ok());
        assert_eq!(r.status(), ProofStatus::Proven);
    }

    #[test]
    fn statuses_serialize_screaming() {
        assert_eq!(serde_json::to_string(&ProofStatus::NotModeled).ok().as_deref(), Some("\"NOT_MODELED\""));
    }
}
