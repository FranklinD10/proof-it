/-!
# State machines

Generic results about transition relations given as `Bool`-valued functions.
Generated per-project proofs (see `src/lean/emit.ts`) instantiate the same
shapes on the concrete state type extracted from source code.
-/
namespace ProofIt.StateMachine

variable {S : Type} (step : S → S → Bool)

/-- Sequences of valid transitions. -/
inductive Reachable : S → S → Prop
  | refl (s : S) : Reachable s s
  | step {a b c : S} : step a b = true → Reachable b c → Reachable a c

/-- A state with no outgoing transitions. -/
def Terminal (t : S) : Prop := ∀ s, step t s = false

/-- Terminal states are absorbing: nothing reachable from them except themselves. -/
theorem terminal_absorbing {t u : S} (ht : Terminal step t) (h : Reachable step t u) : u = t := by
  cases h with
  | refl => rfl
  | @step _ b _ hv _ => rw [ht b] at hv; cases hv

/-- Reachability is transitive. -/
theorem reachable_trans {a b c : S} (h₁ : Reachable step a b) (h₂ : Reachable step b c) :
    Reachable step a c := by
  induction h₁ with
  | refl => exact h₂
  | step hv _ ih => exact Reachable.step hv (ih h₂)

/-- If no transition enters `bad`, then `bad` is reachable only from itself. -/
theorem unenterable {bad : S} (hin : ∀ s, step s bad = false) :
    ∀ a c, Reachable step a c → c = bad → a = bad := by
  intro a c h
  induction h with
  | refl => exact id
  | @step x y z hv _ ih =>
    intro hz
    have hy : y = bad := ih hz
    subst hy
    rw [hin x] at hv
    cases hv

end ProofIt.StateMachine
