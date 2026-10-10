# Assurance for AI-generated changes

Proof-It sits between autonomous coding agents and production. The agent is
**untrusted**: it may write code, tests, candidate properties and proof hints,
but only Proof-It's pipeline (Lean kernel, analyzers, executed tests) produces
evidence. Agent claims are never evidence.

## Proof-carrying changes

```bash
proof-it check --diff origin/main...HEAD --baseline latest --policy /etc/proof-it/policy.yaml --agent coding-agent
```

1. **Affected properties** — changed files plus every module that imports them
   (import graph); properties whose models, findings or applicability signals
   touch those modules. Proof-It decides, not the agent.
2. **Regressions** — PROVEN before, not PROVEN now (or the target vanished);
   new violations of authoritative specifications.
3. **Policy changes** — compared semantically between base and head:
   excluded properties, narrowed includes, new excluded paths, weakened policy
   actions, disabled analyses, newly trusted guard functions, removed terminal
   states or forbidden transitions, new suppressions, changed project
   properties or proof hints. Changes touching a **protected** property block;
   others require a human.
4. **Merge decision** — `AUTO-MERGE ELIGIBLE`, `HUMAN REVIEW REQUIRED` or
   `BLOCKED`, from the organisation's per-tier requirements
   (`formal_proof`, `security_pass`, `adversarial_test`, `regression_pass`,
   `no_violation`). The decision function is specified and proven in Lean
   (`ProofIt.Assurance.decide`: auto-merge only when every requirement is met
   and nothing blocks; any block dominates).
5. **Change bundle** — `.proof-it/changes/<id>/` with the manifest, diff,
   proofs and counterexamples (see evidence-model.md).

## Agent protocol

`proof-it check` prints `proof-it/agent@1` JSON: `status`, `verdict`,
`merge_decision`, `assurance_level`, and `failures[]` with `kind`
(property/finding/regression/policy), `property`, `severity`, `reason`,
`source`, `counterexample` (assignment, steps with source lines, whether it
reproduced against the code, Lean certificate), `assumptions`, `spec_source`,
`recommended_action` and the `explain` command. Exit code 1 when blocked.

## Anti-gaming

- Specifications from the organisation policy cannot be excluded or
  suppressed from the repository.
- Proof hints cannot change theorem statements; forbidden constructs and the
  axiom audit apply.
- Vacuous proofs are refused.
- Hiding code (`exclude`) is a reported policy change.
- AI-generated properties are labelled and never fail a run on their own.
- Names are not evidence. A middleware is credited only with what its code
  can do: one that never denies (no error status, throw or `next(err)`)
  protects nothing, an "admin" guard must read a role, and a guard whose code
  is not in the repository is an opaque condition (UNPROVEN, never PROVEN).
  Local "sanitizers" that return their input unchanged do not clear taint.
  Permanent benchmarks (`benchmarks/authz/noop-*`, `security/noop-sanitizer-bad`)
  keep these tricks from working again.

## Demo

`examples/agent-demo/run.sh` builds a repository where an agent's endpoint
(unit tests passing) leaks another user's location: Proof-It blocks it with a
counterexample; excluding the property instead is blocked; the repaired change
is proven and passes regression checks.
