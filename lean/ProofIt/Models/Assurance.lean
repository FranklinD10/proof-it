/-!
# Proof-It's own decision logic

Specification of the two decisions every Proof-It result rests on, with the
safety properties they must satisfy. The Rust implementation
(`proof_it_core::decision`) is checked against these definitions on every
input by the refinement test in `crates/core/tests/refinement.rs`.
-/
namespace ProofIt.Assurance

inductive Status where
  | proven
  | violated
  | unproven
  deriving DecidableEq, Repr

/-- Evidence produced by the pipeline for one obligation. -/
structure Evidence where
  kernelAccepted : Bool   -- Lean kernel accepted, axioms audited
  vacuous : Bool          -- exhaustive search: hypotheses unsatisfiable
  cexFound : Bool         -- a concrete violating assignment exists in the model
  cexRobust : Bool        -- …for every value of every opaque condition
  assumptionOnly : Bool   -- the conclusion follows from Proof-It's assumptions alone
  deriving DecidableEq, Repr

def classify (e : Evidence) : Status :=
  if e.kernelAccepted && !e.vacuous && !e.assumptionOnly then .proven
  else if e.cexFound && e.cexRobust then .violated
  else .unproven

/-- PROVEN only with kernel acceptance of a non-vacuous theorem. -/
theorem proven_requires_kernel (e : Evidence) :
    classify e = .proven → e.kernelAccepted = true ∧ e.vacuous = false := by
  cases e with
  | mk k v f r a => cases k <;> cases v <;> cases f <;> cases r <;> cases a <;> simp [classify]

/-- PROVEN never rests on assumptions alone: if the conclusion already follows
from what Proof-It assumed (about code it cannot see or interpret), the code
contributed nothing and the theorem proves nothing about it. -/
theorem proven_requires_code (e : Evidence) :
    classify e = .proven → e.assumptionOnly = false := by
  cases e with
  | mk k v f r a => cases k <;> cases v <;> cases f <;> cases r <;> cases a <;> simp [classify]

/-- VIOLATED only with a robust counterexample. -/
theorem violated_requires_robust_cex (e : Evidence) :
    classify e = .violated → e.cexFound = true ∧ e.cexRobust = true := by
  cases e with
  | mk k v f r a => cases k <;> cases v <;> cases f <;> cases r <;> cases a <;> simp [classify]

/-- A counterexample that depends on an opaque condition never yields VIOLATED. -/
theorem opaque_cex_is_not_violation (e : Evidence) (h : e.cexRobust = false) :
    classify e ≠ .violated := by
  cases e with
  | mk k v f r a => cases k <;> cases v <;> cases f <;> cases r <;> cases a <;> simp_all [classify]

inductive Outcome where
  | met
  | needsHuman
  | blocks
  deriving DecidableEq, Repr

inductive Decision where
  | autoMerge
  | humanReview
  | blocked
  deriving DecidableEq, Repr

/-- Merge decision from requirement outcomes and change-level flags
    (`block`: regression, protected-property weakening, high/critical finding;
     `human`: any other verification-policy change). -/
def decide (os : List Outcome) (block human : Bool) : Decision :=
  if block || os.contains .blocks then .blocked
  else if human || os.contains .needsHuman then .humanReview
  else .autoMerge

/-- AUTO-MERGE only if nothing blocks, nothing needs a human, and every requirement is met. -/
theorem auto_merge_sound (os : List Outcome) (block human : Bool) :
    decide os block human = .autoMerge →
      block = false ∧ human = false ∧ ∀ o ∈ os, o = .met := by
  intro h
  unfold decide at h
  split at h
  · exact absurd h (by decide)
  · split at h
    · exact absurd h (by decide)
    · rename_i hb hh
      simp at hb hh
      obtain ⟨hb1, hb2⟩ := hb
      obtain ⟨hh1, hh2⟩ := hh
      refine ⟨hb1, hh1, ?_⟩
      intro o ho
      cases o with
      | met => rfl
      | needsHuman => exact absurd ho hh2
      | blocks => exact absurd ho hb2

/-- Any blocking requirement blocks the change. -/
theorem blocks_dominate (os : List Outcome) (block human : Bool) (h : .blocks ∈ os) :
    decide os block human = .blocked := by
  simp [decide, h]

/-- A regression / protected-property weakening blocks regardless of outcomes. -/
theorem block_flag_dominates (os : List Outcome) (human : Bool) :
    decide os true human = .blocked := by
  simp [decide]

end ProofIt.Assurance
