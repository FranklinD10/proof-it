/-
Truth tables of the decision model, printed for the Rust refinement test.
This file is tooling, not a proof: it evaluates the definitions proven
correct in ProofIt.Models.Assurance.
-/
import ProofIt.Models.Assurance
open ProofIt.Assurance

def bools : List Bool := [false, true]
def outcomeLists : List (List Outcome) :=
  [[], [.met], [.needsHuman], [.blocks], [.met, .met], [.met, .needsHuman], [.needsHuman, .blocks], [.met, .blocks], [.needsHuman, .needsHuman]]

def statusName : Status → String
  | .proven => "PROVEN" | .violated => "VIOLATED" | .unproven => "UNPROVEN"
def decisionName : Decision → String
  | .autoMerge => "AUTO" | .humanReview => "HUMAN" | .blocked => "BLOCKED"
def outcomeName : Outcome → String
  | .met => "met" | .needsHuman => "human" | .blocks => "blocks"

#eval do
  for k in bools do for v in bools do for f in bools do for r in bools do for a in bools do
    IO.println s!"classify {k} {v} {f} {r} {a} {statusName (classify ⟨k, v, f, r, a⟩)}"
  for os in outcomeLists do for b in bools do for h in bools do
    IO.println s!"decide {String.intercalate "," (os.map outcomeName)} {b} {h} {decisionName (decide os b h)}"
