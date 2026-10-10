# Formal verification

## What a PROVEN result means

> The stated property holds **for the model Proof-It extracted from the code**,
> **under the listed assumptions**, and the Lean 4 kernel checked the proof.

It does not mean the program is bug-free. The translation from source code to
the model is performed by Proof-It's extractor and is **not itself verified**;
every proof says so in its assumptions.

## Pipeline for one obligation

1. **Extract.** An extractor turns facts into an obligation
   `∀ vars, hypotheses → conclusion` over a small first-order language
   (integers, identities, booleans, finite enumerations, Bool-valued defs).
2. **Emit.** `lean/emit.rs` renders readable Lean 4: one `inductive` per state
   type, transition tables as `match`, each hypothesis on its own line with the
   source location, and a generic proof (`cases` on finite variables, then
   `simp_all` and `omega`). Generated files import nothing.
3. **Check.** `lean/runner.rs` accepts only if:
   - the source contains none of `sorry`, `admit`, `axiom`, `unsafe`,
     `native_decide`, `implemented_by`, `extern`, `opaque`,
     `debug.skipKernelTC`, `ofReduceBool`, `#eval`, `partial`,
     `decreasing_by`, `termination_by`, `@[csimp]`, `set_option`
     (comments and «quoted» identifiers are ignored);
   - `lean` exits 0 with no `error:` diagnostics;
   - `#print axioms` was printed for every audited theorem;
   - every axiom is one of `propext`, `Quot.sound`, `Classical.choice`
     (a failed proof shows up as `sorryAx` and is rejected).
4. **Non-vacuity.** A kernel-checked theorem is PROVEN only if a concrete state
   satisfying its *meaningfulness condition* exists, and that witness is itself
   checked by Lean with `decide`. If exhaustive search shows the condition is
   unsatisfiable, the result is UNPROVEN ("vacuous").
5. **Not by assumption alone.** Each hypothesis is either read from the code
   (path conditions, a query filtered by the principal, a guard whose code
   names the required role) or *assumed* by Proof-It (a guard's intent it
   cannot confirm, "a lookup by `userId` returns that user's rows", an opaque
   middleware). If exhaustive search shows the conclusion follows from the
   assumed hypotheses alone, the code contributed nothing and the result is
   UNPROVEN ("by assumption only"), even though Lean accepted the theorem.
   Before this rule, a no-op middleware named `requireAdmin` produced a
   kernel-checked `A ∧ True → A`.
6. **Counterexamples.** Without a proof, a bounded search (exhaustive for finite
   domains, boundary values for integers) looks for a violating assignment. It is
   **VIOLATED** only if the violation holds for every value of every *opaque*
   condition (code Proof-It could not interpret), and the assignment is
   certified by Lean (`decide` on the concrete instance).
7. **Otherwise UNPROVEN**, with the Lean error and the search outcome.

The status decision itself is `proof_it_core::decision::classify`, specified in
`lean/ProofIt/Models/Assurance.lean` with kernel-checked theorems
(`proven_requires_kernel`, `proven_requires_code`,
`violated_requires_robust_cex`, `opaque_cex_is_not_violation`) and checked against the Rust implementation on
every input by `crates/core/tests/refinement.rs`.

## Proof quality fields

Every formal result reports: `kernel_checked`, `axioms`, `extra_axioms`,
`unverified_translation` (always true today), `opaque_predicates`,
`non_vacuity` (`kernel-checked-witness`, `witness-found`, `unknown`,
`vacuous`) and `proof_from_hint`.

## Agent proof hints

`.proof-it/proof-hints/<theorem>.lean` may contain a tactic script for a theorem
**Proof-It generated**. Hints are untrusted: the statement is always Proof-It's,
the forbidden-construct scan and the axiom audit apply, and results show
`proof_from_hint = true`.

## Formalization levels

| Level | Meaning |
|---|---|
| 0 | Static analysis only |
| 1 | Property matched (applicability signals) |
| 2 | Formal model generated |
| 3 | Lean theorem checked (or Lean-certified counterexample) |
| 4 | State-space / model verification (not implemented) |
| 5 | System-level verification (not implemented) |

## Models available today

| Extractor | Properties | Proof shape |
|---|---|---|
| `state-machine.terminal` / `.forbidden` | STATE-001, STATE-002 | finite case analysis; multi-step absorption by induction over `Reachable` |
| `authz.ownership` / `authz.write` | AUTHZ-001, AUTHZ-004 | path condition to each response/write ⇒ owner = principal ∨ admin |
| `authz.admin` | AUTHZ-002 | path condition to each successful response ⇒ admin role |
| `ledger.conservation` / `.non-negative` | PAY-001, PAY-003 | symbolic execution over unbounded integers, `omega` |

Reference models with hand-written proofs live in `lean/ProofIt/Models/`
(`lake build` checks them).

## Known limits (stated, not hidden)

- JavaScript numbers are not integers: ledger proofs are about the integer
  model; the attack engine executes the real code with NaN, fractions, numeric
  strings and aliasing to find the gap (and reports it as such).
- Opaque conditions (unknown functions, middleware bodies) make violations
  UNPROVEN rather than VIOLATED.
- Path merging covers `if`/`else`, early exits, `switch`, and `try` with
  swallowing `catch` (only `return`-based exits survive). Loops are not
  unrolled: guards established inside a loop body do not hold after it.
