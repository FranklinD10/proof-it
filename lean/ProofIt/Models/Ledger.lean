/-!
# Ledger transfers

Reference model for PAY-001 (conservation) and PAY-003 (no negative balance).
-/
namespace ProofIt.Ledger

structure Accounts where
  src : Int
  dst : Int

def transfer (a : Accounts) (amt : Int) : Accounts :=
  { src := a.src - amt, dst := a.dst + amt }

/-- PAY-001: a transfer neither creates nor destroys money. -/
theorem transfer_conserves (a : Accounts) (amt : Int) :
    (transfer a amt).src + (transfer a amt).dst = a.src + a.dst := by
  simp [transfer]; omega

/-- PAY-003: with the guard `0 < amt ≤ src`, balances stay non-negative. -/
theorem transfer_nonneg (a : Accounts) (amt : Int)
    (hd : 0 ≤ a.dst) (hpos : 0 < amt) (hcov : amt ≤ a.src) :
    0 ≤ (transfer a amt).src ∧ 0 ≤ (transfer a amt).dst := by
  simp [transfer]; omega

/-- Without the coverage guard the property fails; witness checked by the kernel. -/
theorem unguarded_transfer_overdraws :
    (transfer ⟨5, 0⟩ 7).src < 0 := by decide

end ProofIt.Ledger
