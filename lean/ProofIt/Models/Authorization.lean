/-!
# Resource ownership

The reference model for AUTHZ-001/AUTHZ-002: a request is granted only on a
path whose guards imply ownership (or an explicitly allowed role).
-/
namespace ProofIt.Authorization

inductive Role where
  | admin
  | user
  deriving DecidableEq, Repr

structure Principal where
  id : Nat
  role : Role

structure Resource where
  owner : Nat

/-- The intended policy: owners, and admins, may read. -/
def policy (p : Principal) (r : Resource) : Bool :=
  r.owner == p.id || p.role == .admin

/-- A guarded handler: returns the resource only if `guard` holds. -/
def handler (guard : Principal → Resource → Bool) (p : Principal) (r : Resource) : Option Resource :=
  if guard p r then some r else none

/-- Any handler guarded by a check that implies the policy never leaks a foreign resource. -/
theorem guarded_handler_isolates (guard : Principal → Resource → Bool)
    (sound : ∀ p r, guard p r = true → policy p r = true)
    (p : Principal) (r : Resource) (hNotOwner : r.owner ≠ p.id) (hNotAdmin : p.role ≠ .admin) :
    handler guard p r = none := by
  unfold handler
  split
  · rename_i hg
    have := sound p r hg
    simp [policy] at this
    cases this <;> contradiction
  · rfl

/-- The unguarded handler leaks: a concrete counterexample, checked by the kernel. -/
theorem unguarded_handler_leaks :
    (handler (fun _ _ => true) ⟨1, .user⟩ ⟨2⟩).isSome = true ∧ (2 : Nat) ≠ 1 ∧ policy ⟨1, .user⟩ ⟨2⟩ = false := by
  decide

end ProofIt.Authorization
