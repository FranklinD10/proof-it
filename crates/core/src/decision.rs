//! Proof-It's two load-bearing decisions as pure functions.
//!
//! These are the Rust implementations of `ProofIt.Assurance.classify` and
//! `ProofIt.Assurance.decide` in `lean/ProofIt/Models/Assurance.lean`, where
//! their safety properties are proven (PROVEN needs kernel acceptance of a
//! non-vacuous theorem; VIOLATED needs a robust counterexample; AUTO-MERGE
//! only when nothing blocks or needs a human). `tests/refinement.rs` checks the
//! Rust functions against Lean's evaluation of the definitions on every input.

use crate::types::ProofStatus;

/// Status of one obligation from the evidence the pipeline produced.
/// `assumption_only`: the conclusion follows from Proof-It's assumptions alone.
pub fn classify(kernel_accepted: bool, vacuous: bool, cex_found: bool, cex_robust: bool, assumption_only: bool) -> ProofStatus {
    if kernel_accepted && !vacuous && !assumption_only {
        ProofStatus::Proven
    } else if cex_found && cex_robust {
        ProofStatus::Violated
    } else {
        ProofStatus::Unproven
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Met,
    NeedsHuman,
    Blocks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    AutoMerge,
    HumanReview,
    Blocked,
}

/// Merge decision from requirement outcomes and change-level flags
/// (`block`: regression, protected weakening, high/critical finding in the change;
///  `human`: any other verification-policy change).
pub fn decide(outcomes: &[Outcome], block: bool, human: bool) -> Decision {
    if block || outcomes.contains(&Outcome::Blocks) {
        Decision::Blocked
    } else if human || outcomes.contains(&Outcome::NeedsHuman) {
        Decision::HumanReview
    } else {
        Decision::AutoMerge
    }
}
