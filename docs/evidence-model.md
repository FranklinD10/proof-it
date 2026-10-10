# Evidence model

## Statuses

| Status | Meaning | Required evidence |
|---|---|---|
| `PROVEN` | The property holds for the extracted model under the listed assumptions | Lean kernel acceptance (axioms audited) **and** a non-vacuity witness |
| `VIOLATED` | A concrete counterexample exists | A violating assignment robust to every opaque condition (Lean-certified when Lean is installed), or an input executed against the implementation that breaks the property |
| `UNPROVEN` | Neither | The reason (Lean error, opaque condition, unsupported construct). **Not evidence of a bug.** |
| `NOT_MODELED` | The property applies but has no formal model | Non-formal evidence may exist from its detectors |
| `NOT_APPLICABLE` | No code matched the property | — |
| `ERROR` | Proof-It failed on this target | The error; please report it |

A violation of a specification whose source is `inferred` or `ai-generated`
never fails a run on its own: the requirement itself is a guess and is reported
as a warning until a human declares it.

## Evidence kinds (strongest first)

`kernel-checked`, `kernel-checked-counterexample`, `replayed-against-code`,
`bounded-search`, `static-pattern`, `external-tool`, `assumption`.

## Specification sources

`library` (shipped with Proof-It), `organization` (trusted policy outside the
repository), `project` (repository, written by a human), `ai-generated`
(candidate), `inferred` (heuristic). Always shown next to the result.

## Run directory

```text
.proof-it/runs/<run-id>/
├── report.json        complete report (format proof-it/report@1)
├── summary.json       verdict, counts, level, seed, commit, merge decision
├── results.json       property results
├── findings.json      non-formal findings
├── metadata.json      versions, options, environment, property versions, stages
├── proofs/            generated Lean files, Lean logs, non-vacuity witnesses
├── counterexamples/   counterexample JSON (replayable) and Lean certificates
├── tools/             raw output of external tools (secrets redacted)
└── traces/
```

`.proof-it/runs/LATEST` names the latest run. `.proof-it/cache/proofs/` stores
only **accepted** checks, keyed by sha256(toolchain ‖ Lean source).

## Change bundle

With `--diff`, `.proof-it/changes/PI-<run>-<commit>/` contains `manifest.json`
(format `proof-it/change@1`: merge decision and reasons, affected properties,
counts, regressions, policy changes, the agent name), `diff.patch`,
`properties.json`, `report.json`, `proofs/` and `counterexamples/`.

## Verdicts

`PASSED`, `PASSED WITH WARNINGS`, `FAILED`, or `INCOMPLETE`. A run is
INCOMPLETE when any source file could not be parsed (including recoverable
syntax errors) or was skipped by a size or file-count limit: no result covers
that code, so the run cannot pass. A violation in the analysed part still makes
it FAILED. An incomplete change is never AUTO-MERGE ELIGIBLE, and the assurance
level is 0.

## Assurance levels

| Level | Requirement |
|---|---|
| 0 | Nothing meaningful established |
| 1 | Static and security analysis ran |
| 2 | … and no unsuppressed HIGH/CRITICAL findings |
| 3 | … and every applicable CRITICAL/HIGH property has a formal model |
| 4 | … and every such property is PROVEN against an authoritative specification |
| 5 | … and adversarial testing ran against the code without violations |
| 6 | System-level invariants — not attainable today |

Each report states the level reached and what is missing for the next.

## Reproducibility

Every randomised search uses a recorded seed (default 1337; `--seed`).
Counterexample files contain the obligation and the replay specification;
`proof-it replay <file>` re-checks the model and the Lean certificate.
